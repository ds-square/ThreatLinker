# Changelog

All significant changes to the Threatlinker project will be documented in this file.

## [0.1.0] - YYYY-MM-DD
### Added
- **CVE-CAPEC Correlation**: Added functionality to correlate CVE vulnerabilities with CAPEC attack patterns.
- **Database Update System**: Initial implementation of the update check system for CVE, CWE, CAPEC, and MITRE ATT&CK.
- **Custom Middleware**: Created middleware to redirect users to the update page if no initial data update has been performed.

### Changed
- Refactored views in `core` to improve modularity.
- Updated project structure to separate static files and templates for better organization.

### Fixed
- **Redirection Issue in Middleware**: Fixed a redirection error where non-updated data was not properly directing to the update page.
- **URL Configuration**: Corrected URL namespace issues in `data` app.

## [0.1.1] - YYYY-MM-DD
### Added
- **Entity-Specific Update Phases**: Implemented a modular, multi-phase update process for CVE, CWE, and CAPEC entities, including separate phases for download, import, and relationship creation.
- **Real-Time Update Monitoring**: Added functionality to track and display the progress of each update phase in real-time within the UI.
- **Detailed XML Parsing for CWE**: Improved XML parsing logic for CWE data, including extraction and storage of detailed information such as demonstrative examples, applicable platforms, potential mitigations, and detection methods.

### Changed
- **Enhanced Middleware Logic**: Updated middleware to check and enforce completion of initial data updates before accessing main pages, with exclusions for admin pages.
- **Database Optimization for Updates**: Reduced redundant processing by allowing updates to resume from incomplete phases rather than restarting entirely.
- **Optimized Import Process for CWE**: Modified the CWE import function to avoid early dependency issues by deferring relationship creation to the end of the process.

### Fixed
- **Git Large File Removal**: Successfully removed large JSON files from version history and optimized `.gitignore` to prevent re-adding them to the repository.
- **Namespace Handling in XML Parsing**: Fixed issues with XML namespaces to ensure accurate extraction of CWE data.

## [0.2.0] - YYYY-MM-DD
### Added
- **Automatic Update System**: Developed an automatic update system to keep CVE, CWE, and CAPEC data synchronized with the latest sources. The system is structured into specific phases (download, import, and relationship creation) for each entity, ensuring that updates are handled consistently and can resume from the last incomplete phase in case of interruptions.
- **Statistics Module for CVE, CWE, and CAPEC**: Implemented a statistics module to generate insights across CVE, CWE, and CAPEC data:
  - **CVE Statistics**: Added insights on rating distributions, annual CVE counts, top 20 vendors and products, and the prevalence of CVE-to-CWE relationships.
  - **CWE Statistics**: Developed analytics for the average number of CAPECs per CWE and the distribution of CAPEC links across CWE entries.
  - **CAPEC Statistics**: Analyzed execution flow metrics, distribution of attack steps, and top CAPECs associated with CWE patterns.

### Changed
- **Improved Data Processing for Updates**: Refined the update process for each entity, focusing on optimizing parsing and processing times, especially for CVE, CWE, and CAPEC relationship handling.
- **Admin Views for CVE, CWE, CAPEC Statistics**: Enhanced Django admin views to allow easy visualization of related CAPECs for CWE entries and improved the management of attack patterns.
- **View Organization**: Updated views for `data` app to display real-time statistics for CVE, CWE, and CAPEC entries, along with direct links to key insights, such as the top vendors, products, and CAPEC-to-CWE relationships.

### Fixed
- **View Rendering Issues in Statistics Module**: Corrected alignment issues and improved chart display across different resolutions and devices in the statistics overview.
- **Data Resynchronization**: Fixed bugs related to handling partial data in updates and ensured that resuming updates picks up without redundancy or duplication.

## [0.2.1] - YYYY-MM-DD
### Added
- **CVE, CWE, and CAPEC View Enhancements**: Created dedicated views to allow users to drill down into CVE, CWE, and CAPEC data, including:
  - **CVE View**: Display details of vulnerabilities, including associated CWE relationships and impacted platforms.
  - **CWE View**: Present related CAPECs, relationship types, and exploitation likelihood.
  - **CAPEC View**: Show related CWEs, execution flow details, and attack steps with phase information.
- **Vendor and Product Analysis in CVE Statistics**: Added new analysis for `vulnerable_cpe_uris` field to generate top 20 most frequently mentioned vendors and products across all CVE entries, providing more insight into affected software and hardware.

### Changed
- **Statistics JSON Export Structure**: Updated the JSON structure for the statistics file to ensure more organized and hierarchical data, improving ease of use for charting and further processing.
- **Progress Bar for Updates**: Enhanced the UI progress bar in the update view to display current update phase, percentage completed, and estimated time remaining.
- **Modularized Chart Scripts**: Moved charting scripts into reusable components, making it easier to add new charts or modify existing ones across CVE, CWE, and CAPEC statistics.

### Fixed
- **Chart Labeling for Top Vendors/Products**: Corrected alignment and labeling issues in top vendor and product charts within CVE statistics.
- **Execution Flow Display in CAPEC View**: Resolved issues in displaying execution flow steps within the CAPEC detail view to ensure consistency in showing phases and step details.
- **Update Phase Restart Logic**: Fixed an issue where the update process would erroneously restart from the first phase instead of resuming, improving reliability and reducing redundant processing times.

## [0.3.0] - YYYY-MM-DD
### Added
- **CAPEC Numeric ID Extraction**: Added a method `get_numeric_id` to the CAPEC model to extract the numeric ID from the `CAPEC-XXX` format, allowing for easier sorting and filtering based on CAPEC IDs.
- **Improved CAPEC Score Ordering**: Implemented functionality to sort CAPEC entries by their `final_score` in descending order by default, improving data presentation in tables.
- **Model Score Display Improvements**: Enhanced the table rendering for displaying CAPEC data with model scores for each related model (e.g., SBERT, ATTACKBERT), ensuring scores are correctly matched to the respective CAPECs.
- **Comparisons with SBERT and ATTACKBERT**: Added functionality to compare CAPEC entries using SBERT and ATTACKBERT, allowing for better evaluation of similarity scores between different models.
- **Preprocessed CAPEC Comparison**: Introduced Preprocessed CAPEC entries that can be used for comparison against original CAPECs, supporting a more granular analysis of attack patterns.

### Changed
- **CAPEC Query Filtering**: Updated the `CAPEC` queries to exclude deprecated entries by filtering based on the `status` field, specifically excluding entries marked as 'Deprecated'.
- **Table Sorting Optimization**: Updated the JavaScript sorting functionality to ensure numeric columns (e.g., `final_score`) are correctly sorted in descending order by default, with dynamic sorting on click for any column.
- **Model Name Handling**: Refined the logic for displaying model names and scores in CAPEC-related tables, ensuring that the correct model's score is shown even when there is a mismatch between model names and score data.
- **Preprocessed CAPEC Handling**: Improved the handling of Preprocessed CAPECs by ensuring they are properly linked to CAPEC data and can be used for comparisons in the same table.

### Fixed
- **DataTable Sorting Issue**: Fixed an issue where clicking on the column header to sort did not trigger sorting when numeric scores were involved, ensuring proper interaction with DataTables sorting functionality.
- **CAPEC Score Alignment**: Addressed alignment issues in the display of CAPEC scores to ensure they are correctly associated with the CAPECs and are displayed consistently across different models.
- **Preprocessed CAPEC Comparison**: Resolved issues where Preprocessed CAPECs were not properly compared with the original CAPEC data, ensuring consistent and accurate analysis across both CAPEC and Preprocessed CAPEC models.


## [Unreleased]
### Planned
- **User Management and Permissions**: Adding user roles and permissions to restrict access to update functionalities and sensitive data views.
- **Graph-Based Analytics**: Introducing advanced graphing and network visualizations for threat analysis to highlight connections between CVEs, CWEs, and CAPECs.
- **Automated Report Generation**: Scheduled generation of periodic reports, including CVE trend analysis, vendor-specific vulnerabilities, and attack pattern insights.
