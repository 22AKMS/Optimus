## Demo Note
### For the sake of the Demo, The amount of data we retrieve from NVD's API is limited to the last 15 days and we trigger the refresh manually as not to get rate limited or outright blocked.

<p align="center">
  <img src="https://github.com/22AKMS/Optimus/blob/main/public/apple-touch-icon.png" width="120" />
</p>

<h1 align="center">Optimus</h1>

<p align="center">
  <strong>A CVE Analysis Optimizer</strong>
</p>


<p align="center">
  <a href="#Install">Automatic Install</a> •
  <a href="#Manual-Installation">Manual Installation</a> •
  <a href="#Team-member-responsibilities">Team Responsibilities</a> •
  <a href="#Project-Requirements">Project Requirements</a> •
  <a href="#Diagram">Diagram</a>
</p>


## ⚠️⚠️ Optional Prerequisite ⚠️⚠️

### This app uses data from NVD API. An API key is not required but if you plan on requesting a lot of data without getting rate limited then we recommend getting an API key from here:

https://nvd.nist.gov/developers/request-an-api-key


## Install
You will need to add your Enterprise GitHub credentials to git to be able to clone this project.

Run these commands in Google Cloud Console


### Clone this project
```bash
git clone https://github.itap.purdue.edu/aalsaadi/Optimus/
cd Optimus
```

### Add execute permission to the script and run it 
```bash
chmod +x install_gcloud.sh
npm install
./install_gcloud.sh
```

### Automatic installer parameters
| Parameter | Default | Required | Description |
|---|---:|:---:|---|
| Google Cloud project ID | None | Yes | GCP project where Optimus will be deployed. |
| Region | `us-central1` | Yes | Region for Cloud Run, Cloud Functions, Firestore, and Cloud SQL. |
| Cloud SQL instance name | `cve-analyzer-sql` | Yes | PostgreSQL Cloud SQL instance name. |
| PostgreSQL database name | `cve_analyzer` | Yes | Database used by the web app, functions, and Looker Studio view. |
| PostgreSQL app user | `appuser` | Yes | Database user used by the app and functions. |
| PostgreSQL app user password | None | Yes | Password assigned to the app database user. |
| PostgreSQL postgres admin password | None | Yes | Password assigned to the Cloud SQL `postgres` admin user. |
| Firestore database ID | `cve-analyzer` | Yes | Firestore database used for saved CVEs, watched products, and user state. |
| Cloud Run service name | `cve-analyzer-app` | Yes | Name of the deployed web application service. |
| Service account name | `cve-analyzer-sa` | Yes | Service account used by Cloud Run and Cloud Functions. |
| Sync function name | `syncRecentCves` | Yes | Cloud Function that pulls CVE data from the NVD API. |
| Analytics function name | `refreshTrendAnalytics` | Yes | Cloud Function that refreshes analytics and rebuilds the Looker view. |
| Demo app user ID | `demo-user` | Yes | User key used for demo saved CVEs and watched products. |
| Initial sync window in days | `30` | Yes | Number of recent published days to fetch during the initial NVD sync. |
| Optional NVD API key | Blank | No | NVD API key used to reduce rate limiting. |
| Configure Cloud SQL access for Looker Studio | `Y` | Yes | Creates and configures a read-only PostgreSQL user for Looker Studio. |
| Looker Studio read-only PostgreSQL user | `looker_reader` | If Looker enabled | Database user used by the Looker Studio PostgreSQL connector. |
| Looker Studio read-only PostgreSQL password | None | If Looker enabled | Password assigned to the Looker Studio database user. |
| Authorize Looker Studio connector IP range | `Y` | If Looker enabled | Adds `142.251.74.0/23` to the Cloud SQL authorized networks for Looker Studio. |

## Manual Installation
WIP<!-- ⚠️⚠️ add more here...-->


## Team member responsibilities

- [ ] **Abdulla Alsaadi - Backend / API implementation / Installer / Backend scripts**
- [ ] **Liulseged Abate - Web app / frontend**
- [ ] **Matteo Hodge - Databases / cloud services**
- [ ] **Noah Pumphrey - Functions / deployment / demo**


## Project Requirements
| Requirement | Status | Note |
|---|---|---|
| One relational database | ✅ | Cloud SQL - PostgreSQL |
| One Non-relational database | ✅ | Firestore |
| Google Cloud Function 1 | ✅ | syncRecentCves |
| Google Cloud Function 2 | ✅ | refreshTrentAnalystics |

## Diagram

                           +---------------------------+
                           |         Browser           |
                           |  homepage / CVE detail    |
                           |  filters / watchlist      |
                           +-------------+-------------+
                                         |
                                         | HTTPS
                                         v
                           +---------------------------+
                           |    Cloud Run web app      |
                           |   Node.js / Express       |
                           |   Optimus CVE Analyzer    |
                           +------+--------------+-----+
                                  |              |
                 relational data  |              |  non-relational data
                                  v              v
                    +--------------------+   +--------------------+
                    | Cloud SQL          |   | Firestore          |
                    | PostgreSQL         |   | saved CVEs /       |
                    | CVEs / products /  |   | watchlist /        |
                    | references / stats |   | user state         |
                    +----------+---------+   +--------------------+
                               ^
                               |
                               | ingest / refresh
                               |
                +--------------+------------------------------+
                | Google Cloud Functions                      |
                | 1) syncRecentCves                           |
                |    pulls CVEs from NVD API into Cloud SQL   |
                | 2) refreshTrendAnalytics                    |
                |    updates trend/summary analytics          |
                +--------------+------------------------------+
                               ^
                               |
                               | CVE feed
                               |
                    +----------------------------+
                    | NVD CVE API                |
                    | public vulnerability data  |
                    +----------------------------+

                    +----------------------------+
                    | Looker Studio              |
                    | trend dashboards / charts  |
                    +-------------^--------------+
                                  |
                                  | reads analytics data
                                  |
                           +------+------+
                           |  Cloud SQL  |
                           +-------------+
