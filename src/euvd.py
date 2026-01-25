"""
EUVD (European Union Vulnerability Database) Connector for OpenCTI
Imports vulnerability data from ENISA's EUVD API into OpenCTI.
"""

import hashlib
import os
import re
import time
import traceback
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import requests
import stix2
import yaml
from dateutil.parser import parse as dateutil_parse
from pycti import OpenCTIConnectorHelper, get_config_variable


class EUVDConnector:
    """
    EUVD Connector for OpenCTI.
    
    Fetches vulnerability data from the European Union Vulnerability Database
    (EUVD) API maintained by ENISA and imports them into OpenCTI as STIX
    Vulnerability objects.
    """

    def __init__(self):
        """Initialize the EUVD connector with configuration."""
        # Load configuration from file or environment
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path, encoding="utf-8"), Loader=yaml.SafeLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        
        self.helper = OpenCTIConnectorHelper(config)
        
        # EUVD specific configuration
        self.euvd_base_url = get_config_variable(
            "EUVD_BASE_URL",
            ["euvd", "base_url"],
            self.helper.config,
            default="https://euvdservices.enisa.europa.eu/api",
        )
        
        self.euvd_interval = get_config_variable(
            "EUVD_INTERVAL",
            ["euvd", "interval"],
            self.helper.config,
            isNumber=True,
            default=6,
        )
        
        self.euvd_max_date_range = get_config_variable(
            "EUVD_MAX_DATE_RANGE",
            ["euvd", "max_date_range"],
            self.helper.config,
            isNumber=True,
            default=30,
        )
        
        self.euvd_maintain_data = get_config_variable(
            "EUVD_MAINTAIN_DATA",
            ["euvd", "maintain_data"],
            self.helper.config,
            default=True,
        )
        
        self.euvd_pull_history = get_config_variable(
            "EUVD_PULL_HISTORY",
            ["euvd", "pull_history"],
            self.helper.config,
            default=False,
        )
        
        self.euvd_history_start_year = get_config_variable(
            "EUVD_HISTORY_START_YEAR",
            ["euvd", "history_start_year"],
            self.helper.config,
            isNumber=True,
            default=2024,
        )
        
        self.euvd_min_score = get_config_variable(
            "EUVD_MIN_SCORE",
            ["euvd", "min_score"],
            self.helper.config,
            isNumber=True,
            default=0,
        )
        
        self.euvd_import_exploited_only = get_config_variable(
            "EUVD_IMPORT_EXPLOITED_ONLY",
            ["euvd", "import_exploited_only"],
            self.helper.config,
            default=False,
        )
        
        self.euvd_import_critical_only = get_config_variable(
            "EUVD_IMPORT_CRITICAL_ONLY",
            ["euvd", "import_critical_only"],
            self.helper.config,
            default=False,
        )
        
        # Force run option - bypasses last_run check for testing
        self.euvd_force_run = get_config_variable(
            "EUVD_FORCE_RUN",
            ["euvd", "force_run"],
            self.helper.config,
            default=False,
        )
        
        # Create ENISA identity as the source organization
        self.identity = self._create_enisa_identity()
        
        # API rate limiting - EUVD recommends 1 request per 6 seconds
        self.request_delay = 6
        
        # HTTP session with proper headers
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "OpenCTI-EUVD-Connector/1.0 (https://github.com/OpenCTI-Platform/connectors)",
            "Accept-Language": "en-US,en;q=0.9",
        })
        
        self.helper.log_info("EUVD Connector initialized successfully")

    def _create_enisa_identity(self) -> stix2.Identity:
        """Create ENISA identity as the source organization."""
        return stix2.Identity(
            id="identity--7b82b010-b1c0-4dae-981f-7756374a17df",
            name="European Union Agency for Cybersecurity (ENISA)",
            identity_class="organization",
            description="ENISA is the European Union's agency dedicated to achieving a high common level of cybersecurity across Europe.",
            contact_information="https://www.enisa.europa.eu/",
            created_by_ref="identity--7b82b010-b1c0-4dae-981f-7756374a17df",
        )

    def _parse_euvd_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse EUVD date format.
        
        EUVD returns dates like: "Apr 15, 2025, 8:30:58 PM"
        """
        if not date_str:
            return None
        try:
            return dateutil_parse(date_str)
        except Exception as e:
            self.helper.log_warning(f"Failed to parse date '{date_str}': {e}")
            return None

    def _extract_cve_id(self, aliases: str) -> Optional[str]:
        """Extract CVE ID from aliases string."""
        if not aliases:
            return None
        
        # Aliases are separated by \n
        for alias in aliases.split("\n"):
            alias = alias.strip()
            if alias.startswith("CVE-"):
                return alias
        return None

    def _get_cvss_severity(self, score: float) -> str:
        """
        Convert CVSS score to severity level.
        
        Based on CVSS v3.1 severity ratings:
        - None: 0.0
        - Low: 0.1 - 3.9
        - Medium: 4.0 - 6.9
        - High: 7.0 - 8.9
        - Critical: 9.0 - 10.0
        """
        if score is None or score == 0:
            return "none"
        elif score < 4.0:
            return "low"
        elif score < 7.0:
            return "medium"
        elif score < 9.0:
            return "high"
        else:
            return "critical"

    def _generate_stix_id(self, name: str) -> str:
        """
        Generate a deterministic STIX UUID from a name.
        
        Uses namespace UUID for OpenCTI vulnerabilities to ensure
        consistent IDs across runs.
        """
        # OpenCTI namespace UUID for vulnerabilities
        namespace = "00abedb4-aa42-466c-9c01-fed23315a9b7"
        
        # Create deterministic UUID using SHA-256
        hash_input = f"{namespace}{name}".encode("utf-8")
        hash_digest = hashlib.sha256(hash_input).hexdigest()
        
        # Format as UUID (8-4-4-4-12)
        uuid_str = f"{hash_digest[:8]}-{hash_digest[8:12]}-{hash_digest[12:16]}-{hash_digest[16:20]}-{hash_digest[20:32]}"
        
        return uuid_str

    def _build_external_references(
        self, euvd_id: str, cve_id: Optional[str], references: str
    ) -> list:
        """Build external references list from EUVD data."""
        external_refs = []
        
        # Add EUVD reference
        external_refs.append(
            stix2.ExternalReference(
                source_name="EUVD",
                external_id=euvd_id,
                url=f"https://euvd.enisa.europa.eu/vulnerability/{euvd_id}",
            )
        )
        
        # Add CVE reference if available
        if cve_id:
            cve_number = cve_id.replace("CVE-", "")
            external_refs.append(
                stix2.ExternalReference(
                    source_name="cve",
                    external_id=cve_id,
                    url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                )
            )
        
        # Add additional references from the references field
        if references:
            for ref_url in references.split("\n"):
                ref_url = ref_url.strip()
                if ref_url and ref_url.startswith("http"):
                    try:
                        # Extract source name from URL domain
                        parsed_url = urllib.parse.urlparse(ref_url)
                        source_name = parsed_url.netloc
                        external_refs.append(
                            stix2.ExternalReference(
                                source_name=source_name,
                                url=ref_url,
                            )
                        )
                    except Exception:
                        pass
        
        return external_refs

    def _create_vulnerability(self, vuln_data: dict) -> Optional[stix2.Vulnerability]:
        """
        Create a STIX Vulnerability object from EUVD data.
        
        Args:
            vuln_data: Dictionary containing vulnerability data from EUVD API
            
        Returns:
            STIX Vulnerability object or None if creation fails
        """
        try:
            euvd_id = vuln_data.get("id")
            if not euvd_id:
                self.helper.log_warning("Vulnerability data missing EUVD ID")
                return None
            
            description = vuln_data.get("description", "No description available")
            
            # Parse dates
            date_published = self._parse_euvd_date(vuln_data.get("datePublished"))
            date_updated = self._parse_euvd_date(vuln_data.get("dateUpdated"))
            
            # Get CVSS information
            base_score = vuln_data.get("baseScore")
            base_score_version = vuln_data.get("baseScoreVersion", "3.1")
            base_score_vector = vuln_data.get("baseScoreVector", "")
            
            # Get EPSS score (probability 0.0 - 1.0)
            epss_score = vuln_data.get("epss")
            
            # Extract CVE ID from aliases
            aliases = vuln_data.get("aliases", "")
            cve_id = self._extract_cve_id(aliases)
            
            # Build external references
            references = vuln_data.get("references", "")
            external_refs = self._build_external_references(euvd_id, cve_id, references)
            
            # Get vendor and product information
            vendors = vuln_data.get("enisaIdVendor", [])
            products = vuln_data.get("enisaIdProduct", [])
            
            # Build description with additional information
            full_description = description
            
            if vendors:
                vendor_names = [
                    v.get("vendor", {}).get("name", "Unknown")
                    for v in vendors
                    if v.get("vendor")
                ]
                if vendor_names:
                    full_description += f"\n\n**Affected Vendors:** {', '.join(set(vendor_names))}"
            
            if products:
                product_info = []
                for p in products:
                    prod_name = p.get("product", {}).get("name", "Unknown")
                    prod_version = p.get("product_version", "All versions")
                    product_info.append(f"{prod_name} ({prod_version})")
                if product_info:
                    full_description += f"\n\n**Affected Products:** {', '.join(set(product_info))}"
            
            if epss_score is not None:
                full_description += f"\n\n**EPSS Score:** {epss_score:.4f} ({epss_score * 100:.2f}% probability of exploitation in next 30 days)"
            
            # Create custom properties for OpenCTI
            custom_properties = {
                "x_opencti_base_score": base_score,
                "x_opencti_base_severity": self._get_cvss_severity(base_score) if base_score else "unknown",
            }
            
            if base_score_vector:
                custom_properties["x_opencti_attack_vector"] = base_score_vector
            
            if epss_score is not None:
                custom_properties["x_opencti_epss_score"] = epss_score
                custom_properties["x_opencti_epss_percentile"] = epss_score * 100
            
            # Build labels
            labels = ["euvd"]
            if base_score and base_score >= 9.0:
                labels.append("critical")
            if vuln_data.get("exploited"):
                labels.append("exploited")
            
            # Determine the vulnerability name
            vuln_name = cve_id if cve_id else euvd_id
            
            # Generate deterministic STIX ID
            vuln_uuid = self._generate_stix_id(vuln_name)
            
            # Create the STIX Vulnerability object
            vulnerability = stix2.Vulnerability(
                id=f"vulnerability--{vuln_uuid}",
                name=vuln_name,
                description=full_description,
                created=date_published if date_published else datetime.now(timezone.utc),
                modified=date_updated if date_updated else datetime.now(timezone.utc),
                created_by_ref=self.identity.id,
                external_references=external_refs,
                labels=labels,
                custom_properties=custom_properties,
                allow_custom=True,
            )
            
            return vulnerability
            
        except Exception as e:
            self.helper.log_error(f"Failed to create vulnerability from data: {e}")
            return None

    def _fetch_vulnerabilities(
        self,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        from_score: int = 0,
        to_score: int = 10,
        exploited: bool = False,
        page: int = 0,
        size: int = 100,
    ) -> dict:
        """
        Fetch vulnerabilities from EUVD API.
        
        Args:
            from_date: Start date (YYYY-MM-DD format)
            to_date: End date (YYYY-MM-DD format)
            from_score: Minimum CVSS score (0-10)
            to_score: Maximum CVSS score (0-10)
            exploited: Only fetch exploited vulnerabilities
            page: Page number (0-indexed)
            size: Number of results per page (max 100)
            
        Returns:
            Dictionary with 'items' list and 'total' count
        """
        params = {
            "assigner": "",
            "product": "",
            "vendor": "",
            "text": "",
            "fromDate": from_date or "",
            "toDate": to_date or "",
            "fromScore": from_score,
            "toScore": to_score,
            "fromEpss": 0,
            "toEpss": 100,
            "exploited": str(exploited).lower(),
            "page": page,
            "size": min(size, 100),  # API max is 100
        }
        
        url = f"{self.euvd_base_url}/search"
        
        try:
            self.helper.log_debug(f"Fetching EUVD data: {url} with params: {params}")
            response = self.session.get(
                url,
                params=params,
                timeout=60,
            )
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"Failed to fetch EUVD data: {e}")
            return {"items": [], "total": 0}

    def _fetch_latest_vulnerabilities(self) -> list:
        """Fetch the latest vulnerabilities from EUVD."""
        url = f"{self.euvd_base_url}/lastvulnerabilities"
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"Failed to fetch latest vulnerabilities: {e}")
            return []

    def _fetch_exploited_vulnerabilities(self) -> list:
        """Fetch the latest exploited vulnerabilities from EUVD."""
        url = f"{self.euvd_base_url}/exploitedvulnerabilities"
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"Failed to fetch exploited vulnerabilities: {e}")
            return []

    def _fetch_critical_vulnerabilities(self) -> list:
        """Fetch the latest critical vulnerabilities from EUVD."""
        url = f"{self.euvd_base_url}/criticalvulnerabilities"
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            self.helper.log_error(f"Failed to fetch critical vulnerabilities: {e}")
            return []

    def _process_vulnerabilities(self, work_id: str) -> int:
        """
        Process and import vulnerabilities based on configuration.
        
        Args:
            work_id: OpenCTI work ID for tracking progress
            
        Returns:
            Number of vulnerabilities processed
        """
        total_processed = 0
        stix_objects = [self.identity]
        
        # Determine date range
        if self.euvd_pull_history:
            # Pull historical data starting from specified year
            from_date = f"{self.euvd_history_start_year}-01-01"
            to_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        elif self.euvd_maintain_data:
            # Get data from last run or default range
            state = self.helper.get_state()
            if state and "last_run" in state and state.get("vulnerabilities_processed", 0) > 0:
                # Only use last_run if previous run was successful (processed > 0)
                last_run = datetime.fromisoformat(state["last_run"].replace("Z", "+00:00"))
                from_date = last_run.strftime("%Y-%m-%d")
            else:
                # First run or previous run failed - use max_date_range
                from_date = (
                    datetime.now(timezone.utc) - timedelta(days=self.euvd_max_date_range)
                ).strftime("%Y-%m-%d")
            to_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        else:
            # Default: last max_date_range days
            from_date = (
                datetime.now(timezone.utc) - timedelta(days=self.euvd_max_date_range)
            ).strftime("%Y-%m-%d")
            to_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        
        self.helper.log_info(f"Fetching EUVD vulnerabilities from {from_date} to {to_date}")
        
        # Handle different import modes
        if self.euvd_import_exploited_only:
            self.helper.log_info("Importing exploited vulnerabilities only")
            vulnerabilities = self._fetch_with_pagination(
                from_date=from_date,
                to_date=to_date,
                from_score=self.euvd_min_score,
                exploited=True,
            )
        elif self.euvd_import_critical_only:
            self.helper.log_info("Importing critical vulnerabilities only (CVSS >= 9.0)")
            vulnerabilities = self._fetch_with_pagination(
                from_date=from_date,
                to_date=to_date,
                from_score=9.0,
                exploited=False,
            )
        else:
            # Import all vulnerabilities above minimum score
            vulnerabilities = self._fetch_with_pagination(
                from_date=from_date,
                to_date=to_date,
                from_score=self.euvd_min_score,
                exploited=False,
            )
        
        self.helper.log_info(f"Retrieved {len(vulnerabilities)} vulnerabilities from EUVD")
        
        # Convert to STIX objects
        for vuln_data in vulnerabilities:
            vuln_stix = self._create_vulnerability(vuln_data)
            if vuln_stix:
                stix_objects.append(vuln_stix)
                total_processed += 1
        
        # Send STIX bundle to OpenCTI
        if len(stix_objects) > 1:  # More than just the identity
            bundle = stix2.Bundle(objects=stix_objects, allow_custom=True)
            self.helper.send_stix2_bundle(
                bundle.serialize(),
                update=self.euvd_maintain_data,
                work_id=work_id,
            )
            self.helper.log_info(f"Sent {total_processed} vulnerabilities to OpenCTI")
        else:
            self.helper.log_info("No vulnerabilities to import")
        
        return total_processed

    def _fetch_with_pagination(
        self,
        from_date: str,
        to_date: str,
        from_score: float = 0,
        exploited: bool = False,
    ) -> list:
        """
        Fetch all vulnerabilities with pagination.
        
        EUVD API has a maximum of 100 results per page.
        
        Args:
            from_date: Start date (YYYY-MM-DD)
            to_date: End date (YYYY-MM-DD)
            from_score: Minimum CVSS score
            exploited: Only exploited vulnerabilities
            
        Returns:
            List of all vulnerability data
        """
        all_vulnerabilities = []
        page = 0
        page_size = 100
        
        while True:
            self.helper.log_debug(f"Fetching page {page}")
            
            result = self._fetch_vulnerabilities(
                from_date=from_date,
                to_date=to_date,
                from_score=int(from_score),
                to_score=10,
                exploited=exploited,
                page=page,
                size=page_size,
            )
            
            items = result.get("items", [])
            total = result.get("total", 0)
            
            if not items:
                break
            
            all_vulnerabilities.extend(items)
            
            # Check if we've fetched all pages
            if len(all_vulnerabilities) >= total or len(items) < page_size:
                break
            
            page += 1
            
            # Rate limiting
            time.sleep(self.request_delay)
        
        return all_vulnerabilities

    def run(self) -> None:
        """
        Main connector loop.
        
        Runs the connector at the configured interval to fetch and import
        vulnerabilities from EUVD.
        """
        self.helper.log_info("Starting EUVD Connector")
        
        # Main loop
        get_run_and_terminate = getattr(
            self.helper, "connect_run_and_terminate", False
        )
        
        while True:
            try:
                # Get current timestamp for work tracking
                timestamp = int(datetime.now(timezone.utc).timestamp())
                current_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
                
                # Check if we should run based on last run time
                current_state = self.helper.get_state()
                if not self.euvd_force_run and current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    last_run_dt = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                    # Check if enough time has passed
                    next_run = last_run_dt + timedelta(hours=self.euvd_interval)
                    if datetime.now(timezone.utc) < next_run:
                        wait_seconds = (next_run - datetime.now(timezone.utc)).total_seconds()
                        self.helper.log_info(
                            f"Connector will not run until {next_run.strftime('%Y-%m-%d %H:%M:%S')} UTC. "
                            f"Sleeping for {int(wait_seconds)} seconds."
                        )
                        time.sleep(min(wait_seconds, 60))  # Sleep max 60s then recheck
                        continue
                
                # Create work entry
                friendly_name = f"EUVD Connector run @ {current_time}"
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id,
                    friendly_name,
                )
                
                self.helper.log_info(f"EUVD Connector run starting at {current_time}")
                
                try:
                    # Process vulnerabilities
                    processed = self._process_vulnerabilities(work_id)
                    
                    # Update state
                    self.helper.set_state(
                        {
                            "last_run": datetime.now(timezone.utc).isoformat(),
                            "vulnerabilities_processed": processed,
                        }
                    )
                    
                    # Mark work as completed
                    message = f"Connector successfully run, processed {processed} vulnerabilities"
                    self.helper.log_info(message)
                    self.helper.api.work.to_processed(work_id, message)
                    
                except Exception as e:
                    self.helper.log_error(f"Error during processing: {e}")
                    self.helper.api.work.to_processed(work_id, str(e), in_error=True)
                    raise
                
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stopped by user")
                break
            except Exception as e:
                self.helper.log_error(f"Connector run failed: {e}")
                self.helper.log_error(traceback.format_exc())
                # Sleep before retry on error
                time.sleep(60)
            
            # Check run_and_terminate mode
            if get_run_and_terminate:
                self.helper.log_info("Run and terminate mode - exiting")
                break
            
            # Sleep for a short period before next iteration
            time.sleep(60)
