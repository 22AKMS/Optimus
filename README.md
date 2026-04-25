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

WIP<!-- ⚠️⚠️ add more here...-->

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
