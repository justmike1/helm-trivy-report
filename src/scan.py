import argparse
import glob
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request

import yaml

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


class VulnerabilityScanner:
    MAX_RETRIES = 3
    RETRY_DELAY = 5

    @staticmethod
    def get_all_images(repo, version=None):
        """Pull the chart to a temp dir, recursively scan all YAML files for image references."""
        tmp_dir = tempfile.mkdtemp(prefix="vuln-scan-")
        logging.info(f"Pulling chart to {tmp_dir}")

        try:
            # Extract chart into tmp dir
            if os.path.isfile(repo) and (
                repo.endswith(".tgz") or repo.endswith(".tar.gz")
            ):
                # Local .tgz archive — extract directly
                logging.info(f"Extracting local chart archive: {repo}")
                with tarfile.open(repo, "r:gz") as tar:
                    tar.extractall(path=tmp_dir)
            elif os.path.isdir(repo):
                # Local chart directory — copy it
                logging.info(f"Copying local chart directory: {repo}")
                chart_name = os.path.basename(os.path.normpath(repo))
                shutil.copytree(repo, os.path.join(tmp_dir, chart_name))
            else:
                # Remote repo — use helm pull
                pull_cmd = ["helm", "pull", repo, "--untar", "--destination", tmp_dir]
                if version:
                    pull_cmd += ["--version", version]
                logging.debug(f"Running: {' '.join(pull_cmd)}")
                result = subprocess.run(pull_cmd, capture_output=True, text=True)
                if result.returncode != 0:
                    logging.error(
                        f"Helm pull failed (exit {result.returncode}):\n{result.stderr}"
                    )
                    return set()

            # Recursively find all .yaml and .yml files only under charts/ directories
            yaml_files = [
                f
                for f in glob.glob(
                    os.path.join(tmp_dir, "**", "*.yaml"), recursive=True
                )
                + glob.glob(os.path.join(tmp_dir, "**", "*.yml"), recursive=True)
                if os.sep + "charts" + os.sep in f
            ]
            logging.info(f"Found {len(yaml_files)} YAML files in sub-charts")

            images = set()
            image_pattern = re.compile(
                r"""(?:image|repository)["']?\s*:\s*["']?([a-zA-Z0-9._\-/]+(?::[a-zA-Z0-9._\-]+)?)["']?"""
            )

            for yaml_file in yaml_files:
                try:
                    with open(yaml_file, "r") as f:
                        content = f.read()

                    # Parse YAML to find image fields in structured data
                    try:
                        docs = list(yaml.safe_load_all(content))
                    except yaml.YAMLError:
                        docs = []

                    VulnerabilityScanner._extract_images_from_yaml(docs, images)

                    # Also do regex scan for image references that may be in templates
                    for line in content.splitlines():
                        stripped = line.strip()
                        # Skip commented lines and template-only lines
                        if stripped.startswith("#"):
                            continue
                        match = image_pattern.search(stripped)
                        if match:
                            img = match.group(1)
                            # Filter out template placeholders and null values
                            if "{{" not in img and img not in ("null", "None", ""):
                                images.add(img)

                except Exception as e:
                    logging.debug(f"Error reading {yaml_file}: {e}")

            logging.info(f"Found {len(images)} unique images")
            for img in sorted(images):
                logging.debug(f"  Image: {img}")
            if not images:
                logging.warning("No images found in chart files.")
            return images

        finally:
            logging.debug(f"Cleaning up temp dir: {tmp_dir}")
            shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def _extract_images_from_yaml(obj, images):
        """Recursively walk parsed YAML to find image references."""
        if isinstance(obj, dict):
            # Check for image dict with repository field (e.g. image.repository: "accounts-service")
            if "image" in obj and isinstance(obj["image"], dict):
                img_dict = obj["image"]
                if "repository" in img_dict:
                    repo = str(img_dict["repository"])
                    tag = str(img_dict.get("tag", "latest") or "latest")
                    if "{{" not in repo and repo not in ("null", "None", ""):
                        images.add(f"{repo}:{tag}")
            # Check for image field directly as a string
            elif "image" in obj:
                val = obj["image"]
                if (
                    isinstance(val, str)
                    and "{{" not in val
                    and val not in ("null", "None", "")
                ):
                    images.add(val)

            # Check for standalone repository + tag pattern (not nested under image)
            if "repository" in obj and "tag" in obj and "image" not in obj:
                repo = str(obj["repository"])
                tag = str(obj.get("tag", "latest") or "latest")
                if "{{" not in repo and repo not in ("null", "None", ""):
                    images.add(f"{repo}:{tag}")

            for value in obj.values():
                VulnerabilityScanner._extract_images_from_yaml(value, images)
        elif isinstance(obj, list):
            for item in obj:
                VulnerabilityScanner._extract_images_from_yaml(item, images)

    def __init__(self, repo, version=None, registry=None):
        self.images = self.get_all_images(repo, version)
        if registry:
            self.images = self._apply_registry(self.images, registry)
        self.html_files = []

    @staticmethod
    def _apply_registry(images, registry):
        """Prefix images with the given registry. Strips existing registry if present."""
        registry = registry.rstrip("/")
        updated = set()
        for img in images:
            # Split image into name:tag
            if ":" in img:
                name, tag = img.rsplit(":", 1)
            else:
                name, tag = img, "latest"

            # Strip existing registry — keep only the last path segment(s) as the service name
            # e.g. "docker.io/library/nginx" -> "nginx", "quay.io/org/svc" -> "org/svc"
            parts = name.split("/")
            if "." in parts[0] or ":" in parts[0]:
                # First segment looks like a registry (contains dot or port), strip it
                service_name = "/".join(parts[1:])
            else:
                service_name = name

            new_image = f"{registry}/{service_name}:{tag}"
            logging.debug(f"Registry rewrite: {img} -> {new_image}")
            updated.add(new_image)
        logging.info(f"Applied registry prefix: {registry} to {len(updated)} images")
        return updated

    @staticmethod
    def _process_template(template_path, show_links):
        """Preprocess the HTML template to include/exclude links sections.

        Conditional blocks are marked with {{/* LINKS_ONLY */}} ... {{/* END_LINKS_ONLY */}}.
        The placeholder __TOTAL_COLS__ is replaced with the correct colspan value.
        """
        with open(template_path, "r") as f:
            content = f.read()

        if show_links:
            # Keep LINKS_ONLY block contents, strip the markers
            content = content.replace("{{/* LINKS_ONLY */}}\n", "")
            content = content.replace("{{/* END_LINKS_ONLY */}}\n", "")
            content = content.replace("__TOTAL_COLS__", "6")
        else:
            # Remove LINKS_ONLY blocks entirely (markers + content)
            content = re.sub(
                r"\{\{/\* LINKS_ONLY \*/\}\}\n.*?\{\{/\* END_LINKS_ONLY \*/\}\}\n",
                "",
                content,
                flags=re.DOTALL,
            )
            content = content.replace("__TOTAL_COLS__", "5")

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".tpl", delete=False)
        tmp.write(content)
        tmp.close()
        return tmp.name

    def run_trivy_scan(
        self, image, show_links=True, severity_levels="LOW,MEDIUM,HIGH,CRITICAL"
    ):
        html_file_name = f"{image.replace('/', '_').replace(':', '_')}.html"
        html_file_path = os.path.join(os.getcwd(), html_file_name)
        if html_file_path not in self.html_files:
            self.html_files.append(html_file_path)

        templates_dir = os.path.join(
            os.path.abspath(os.path.dirname(__file__)), "templates"
        )
        template_path = os.path.join(templates_dir, "html.tpl")
        processed_template = self._process_template(template_path, show_links)

        try:
            trivy_cmd = [
                "trivy",
                "image",
                "-q",
                "--severity",
                severity_levels,
                "-f",
                "template",
                "--template",
                f"@{processed_template}",
                "-o",
                html_file_path,
                "--scanners",
                "vuln",
                image,
            ]

            retries = 0
            while retries < self.MAX_RETRIES:
                logging.debug("Running command: %s", " ".join(trivy_cmd))
                result = subprocess.run(trivy_cmd, capture_output=True, text=True)

                if result.returncode == 0:
                    logging.info(f"Trivy scan completed for image {image}")
                    return html_file_path
                elif "TOOMANYREQUESTS" in result.stderr:
                    retries += 1
                    logging.warning(
                        f"Rate limit error for image {image}. Retrying {retries}/{self.MAX_RETRIES} after {self.RETRY_DELAY} seconds."
                    )
                    time.sleep(self.RETRY_DELAY)
                else:
                    logging.error(f"Error running Trivy for image {image}: {result.stderr}")
                    return None

            logging.error(
                f"Trivy scan failed after {self.MAX_RETRIES} retries for image {image}"
            )
            return None
        finally:
            if os.path.exists(processed_template):
                os.unlink(processed_template)

    def scan(
        self,
        retries=3,
        exclude_patterns=None,
        exclude_regex=None,
        show_links=True,
        severity_levels="LOW,MEDIUM,HIGH,CRITICAL",
        slack_token=None,
        slack_channel=None,
        slack_mention=None,
    ):
        exclude_patterns = exclude_patterns or []
        exclude_re = re.compile(exclude_regex) if exclude_regex else None

        scannable = []
        for img in self.images:
            if any(pattern in img for pattern in exclude_patterns):
                continue
            if exclude_re and exclude_re.search(img):
                continue
            scannable.append(img)

        excluded = len(self.images) - len(scannable)
        if excluded:
            reasons = []
            if exclude_patterns:
                reasons.append(f"substrings: {', '.join(exclude_patterns)}")
            if exclude_re:
                reasons.append(f"regex: {exclude_regex}")
            logging.info(
                f"Scanning {len(scannable)} images (excluded {excluded} matching {'; '.join(reasons)})"
            )
        else:
            logging.info(f"Scanning {len(scannable)} images")

        failed = []
        for image in scannable:
            try:
                result = self.run_trivy_scan(
                    image, show_links=show_links, severity_levels=severity_levels
                )
                if result is None:
                    failed.append(image)
            except Exception as exc:
                logging.error(f"Image {image} generated an exception: {exc}")
                failed.append(image)

        # Retry failed images
        for attempt in range(1, retries + 1):
            if not failed:
                break
            logging.info(
                f"Retrying {len(failed)} failed images (attempt {attempt}/{retries})"
            )
            still_failed = []
            for image in failed:
                try:
                    result = self.run_trivy_scan(
                        image, show_links=show_links, severity_levels=severity_levels
                    )
                    if result is None:
                        still_failed.append(image)
                except Exception as exc:
                    logging.error(f"Image {image} generated an exception: {exc}")
                    still_failed.append(image)
            failed = still_failed

        if failed:
            logging.warning(
                f"{len(failed)} images failed after all retries: {', '.join(failed)}"
            )

        # Combine all HTML files into final report
        report_file_path = os.path.join(os.getcwd(), "report.html")
        written = 0
        with open(report_file_path, "w") as outfile:
            for html_file in self.html_files:
                if os.path.exists(html_file):
                    with open(html_file) as infile:
                        outfile.write(infile.read())
                    written += 1
                else:
                    logging.warning(f"Missing HTML report: {html_file}")
        logging.info(
            f"Combined {written}/{len(self.html_files)} scan results into report"
        )

        # Sort vulnerability rows by severity (CRITICAL > HIGH > MEDIUM > LOW)
        self._sort_report_by_severity(report_file_path)

        # Remove temporary per-image HTML files
        for html_file in self.html_files:
            if os.path.exists(html_file):
                os.remove(html_file)

        # Convert HTML report to PDF using headless Chrome/Chromium
        pdf_report_path = report_file_path.replace(".html", ".pdf")
        chrome_path = self._find_chrome()
        if chrome_path:
            try:
                pdf_cmd = [
                    chrome_path,
                    "--headless",
                    "--disable-gpu",
                    "--no-sandbox",
                    "--print-to-pdf-no-header",
                    f"--print-to-pdf={pdf_report_path}",
                    report_file_path,
                ]
                logging.debug(f"Running: {' '.join(pdf_cmd)}")
                result = subprocess.run(
                    pdf_cmd, capture_output=True, text=True, timeout=120
                )
                if result.returncode == 0 and os.path.exists(pdf_report_path):
                    os.remove(report_file_path)
                    logging.info(
                        f"Vulnerability scanning complete. Report saved as {pdf_report_path}"
                    )
                else:
                    logging.warning(
                        f"PDF conversion failed: {result.stderr}. HTML report kept at {report_file_path}"
                    )
            except subprocess.TimeoutExpired:
                logging.warning(
                    f"PDF conversion timed out. HTML report kept at {report_file_path}"
                )
            except Exception as e:
                logging.warning(
                    f"PDF conversion error: {e}. HTML report kept at {report_file_path}"
                )
        else:
            logging.warning(
                "Chrome/Chromium not found. Install Google Chrome for PDF output."
            )
            logging.info(
                f"Vulnerability scanning complete. Report saved as {report_file_path}"
            )

        # Send to Slack if configured
        final_report = pdf_report_path if os.path.exists(pdf_report_path) else report_file_path
        if slack_token and slack_channel and os.path.exists(final_report):
            self.send_to_slack(final_report, slack_token, slack_channel, slack_mention)

    @staticmethod
    def _sort_report_by_severity(report_file_path):
        """Sort vulnerability table rows by severity: CRITICAL > HIGH > MEDIUM > LOW."""
        try:
            with open(report_file_path, "r") as f:
                content = f.read()

            # Find all severity-classed <tr> blocks and sort them within each table section
            severity_row_pattern = re.compile(
                r'(<tr class="severity-(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)">.*?</tr>)',
                re.DOTALL,
            )

            def sort_rows(match_section):
                rows = severity_row_pattern.findall(match_section)
                if not rows:
                    return match_section
                rows.sort(key=lambda r: SEVERITY_ORDER.get(r[1], 99))
                return "\n".join(r[0] for r in rows)

            # Split by sub-header rows to sort within each section
            sections = re.split(
                r'(<tr class="sub-header">.*?</tr>)', content, flags=re.DOTALL
            )
            result_parts = []
            for i, section in enumerate(sections):
                if 'class="sub-header"' in section:
                    result_parts.append(section)
                elif severity_row_pattern.search(section):
                    # Sort rows within this section
                    rows = severity_row_pattern.findall(section)
                    if rows:
                        rows.sort(key=lambda r: SEVERITY_ORDER.get(r[1], 99))
                        sorted_rows = "\n      ".join(r[0] for r in rows)
                        # Replace original rows with sorted ones
                        cleaned = severity_row_pattern.sub("", section).rstrip()
                        result_parts.append(cleaned + "\n      " + sorted_rows)
                    else:
                        result_parts.append(section)
                else:
                    result_parts.append(section)

            sorted_content = "".join(result_parts)
            with open(report_file_path, "w") as f:
                f.write(sorted_content)
            logging.info("Report sorted by severity level")
        except Exception as e:
            logging.warning(f"Could not sort report by severity: {e}")

    @staticmethod
    def send_to_slack(report_path, slack_token, slack_channel, slack_mention=None):
        """Upload the report file to a Slack channel and optionally mention a user/group."""
        if not slack_token or not slack_channel:
            logging.debug("Slack token or channel not provided, skipping Slack upload.")
            return

        logging.info(f"Uploading report to Slack channel {slack_channel}")

        # Post an initial message (with optional mention)
        message = ":rotating_light: *Trivy Vulnerability Report*"
        if slack_mention:
            message = f"{slack_mention} {message}"

        try:
            # Upload the file using files.upload v2 API
            file_size = os.path.getsize(report_path)
            file_name = os.path.basename(report_path)

            # Step 1: Get upload URL
            get_url_params = urllib.parse.urlencode(
                {"filename": file_name, "length": file_size}
            ).encode()
            get_url_req = urllib.request.Request(
                "https://slack.com/api/files.getUploadURLExternal",
                data=get_url_params,
                headers={
                    "Authorization": f"Bearer {slack_token}",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                method="POST",
            )
            with urllib.request.urlopen(get_url_req) as resp:
                url_data = json.loads(resp.read().decode())

            if not url_data.get("ok"):
                logging.error(f"Slack getUploadURLExternal failed: {url_data.get('error')}")
                return

            upload_url = url_data["upload_url"]
            file_id = url_data["file_id"]

            # Step 2: Upload file content
            with open(report_path, "rb") as f:
                file_data = f.read()

            upload_req = urllib.request.Request(
                upload_url,
                data=file_data,
                headers={"Content-Type": "application/octet-stream"},
                method="POST",
            )
            with urllib.request.urlopen(upload_req) as resp:
                resp.read()

            # Step 3: Complete the upload and share to channel
            complete_payload = json.dumps(
                {
                    "files": [{"id": file_id, "title": file_name}],
                    "channel_id": slack_channel,
                    "initial_comment": message,
                }
            ).encode()
            complete_req = urllib.request.Request(
                "https://slack.com/api/files.completeUploadExternal",
                data=complete_payload,
                headers={
                    "Authorization": f"Bearer {slack_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(complete_req) as resp:
                complete_data = json.loads(resp.read().decode())

            if complete_data.get("ok"):
                logging.info("Report uploaded to Slack successfully.")
            else:
                logging.error(f"Slack completeUploadExternal failed: {complete_data.get('error')}")

        except Exception as e:
            logging.error(f"Failed to send report to Slack: {e}")

    @staticmethod
    def _find_chrome():
        """Find Chrome/Chromium binary on the system."""
        candidates = [
            # macOS
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
            # Linux
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
        ]
        for candidate in candidates:
            if os.path.isfile(candidate):
                return candidate
            # Check if it's in PATH
            if shutil.which(candidate):
                return candidate
        return None


def main():
    parser = argparse.ArgumentParser(
        description="Scan a Helm chart for vulnerabilities."
    )
    parser.add_argument("--repo", type=str, help="The Helm chart repository to scan.")
    parser.add_argument(
        "--version",
        type=str,
        help="The version of the Helm chart to scan.",
        default=None,
    )
    parser.add_argument(
        "--registry",
        type=str,
        default=None,
        help="Registry prefix for images (e.g. <AWS_ACCOUNT_ID>.dkr.ecr.eu-central-1.amazonaws.com). "
        "Replaces existing registry in discovered image references.",
    )
    parser.add_argument(
        "--exclude-images",
        type=str,
        default="",
        help="Comma-separated list of substrings to exclude images (e.g. --exclude-images postgresql,redis).",
    )
    parser.add_argument(
        "--exclude-images-regex",
        type=str,
        default=None,
        help="Regex pattern to exclude matching images (e.g. --exclude-images-regex 'tickets-.*|legacy-').",
    )
    parser.add_argument(
        "--severity-levels",
        type=str,
        default="LOW,MEDIUM,HIGH,CRITICAL",
        help="Comma-separated severity levels to include (default: LOW,MEDIUM,HIGH,CRITICAL).",
    )
    parser.add_argument(
        "--show-links",
        action="store_true",
        default=False,
        help="Show vulnerability reference links in the report (default: hidden).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=3,
        help="Number of times to retry failed image scans (default: 3).",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="The log level.",
    )
    parser.add_argument(
        "--slack-token",
        type=str,
        default=None,
        help="Slack Bot OAuth token (xoxb-...) for uploading the report. "
        "Requires chat:write and files:write scopes.",
    )
    parser.add_argument(
        "--slack-channel",
        type=str,
        default=None,
        help="Slack channel ID to send the report to (e.g. C0A6S3KNNLW).",
    )
    parser.add_argument(
        "--slack-mention",
        type=str,
        default=None,
        help="Slack mention to include in the message "
        '(e.g. "<!subteam^S0A6S3KNNLW>" for a user group, or "<@U012345>" for a user).',
    )
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(level=args.log_level, format="[%(levelname)s] %(message)s")

    # Create a handler for stdout if it doesn't already exist
    stdout_handler = logging.StreamHandler()
    stdout_handler.setLevel(args.log_level)
    logger = logging.getLogger()
    if not logger.handlers:
        logger.addHandler(stdout_handler)

    if not args.repo:
        parser.error("--repo argument is required.")

    exclude_patterns = (
        [p.strip() for p in args.exclude_images.split(",") if p.strip()]
        if args.exclude_images
        else []
    )
    scanner = VulnerabilityScanner(args.repo, args.version, args.registry)
    severity = ",".join(
        s.strip().upper() for s in args.severity_levels.split(",") if s.strip()
    )
    scanner.scan(
        retries=args.retries,
        exclude_patterns=exclude_patterns,
        exclude_regex=args.exclude_images_regex,
        show_links=args.show_links,
        severity_levels=severity,
        slack_token=args.slack_token,
        slack_channel=args.slack_channel,
        slack_mention=args.slack_mention,
    )


if __name__ == "__main__":
    main()
