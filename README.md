# AetherScan

AetherScan is a privacy-focused personal search engine and desktop browser built with Python, Flask, and PyQt6. It brings together web search, media search, bookmarks, browser tabs, downloads, AI features, and built-in games in a single desktop app.

Search the web, images, videos, news, sports, maps, movies, and more in one app without being locked into a single provider.

## Features

- Web search using multiple public sources
- Image, video, news, sports, map, and movie search
- Optional AI overview and AI chat
- Optional TMDb movie metadata and watch-provider links
- Desktop browser window with tabs
- Bookmarks, history, downloads, tab groups, and session restore
- Built-in games at `/games`
- Core search features work without API keys
- Privacy-focused design

## Requirements

- Windows, macOS, or Linux
- Python 3.10 or newer recommended
- Git or a downloaded copy of the repository
- Internet connection

## Quick Start

### Windows (PowerShell)

```powershell
git clone https://github.com/worldcup2019/Aetherscan.git
cd Aetherscan

py -m venv .venv
.venv\Scripts\Activate.ps1

py -m pip install --upgrade pip
py -m pip install -r requirements.txt python-dotenv

Copy-Item .env.example.txt .env
# Edit .env and set at least:
# SECRET_KEY=change-this-to-a-long-random-string

py app.py
If the desktop window does not appear, open this in a browser:

Text
http://127.0.0.1:5006
macOS / Linux
bash
git clone https://github.com/worldcup2019/Aetherscan.git
cd Aetherscan

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt python-dotenv

cp .env.example.txt .env
# Edit .env and set at least:
# SECRET_KEY=change-this-to-a-long-random-string

python3 app.py
If the desktop window does not appear, open this in a browser:

Text
http://127.0.0.1:5006
If PowerShell blocks activation
PowerShell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.venv\Scripts\Activate.ps1
Environment Variables
The project includes a sample environment file: .env.example.txt.

Copy it to .env and add only the keys you want to use.

env
# Required for real sessions/logins in production
SECRET_KEY=change-this-to-a-long-random-string

# AI Overview + AI Chat (optional)
GEMINI_API_KEY=
GEMINI_MODEL=gemini-3.8-flash
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-5
GROQ_API_KEY=
GROQ_MODEL=llama-3.3-70b-versatile

# Movies tab
TMDB_API_KEY=

# Maps tab (3D globe)
CESIUM_ION_TOKEN=

# Optional extra search sources
BRAVE_API_KEY=
SERPAPI_API_KEY=
BING_API_KEY=
GOOGLE_CSE_API_KEY=
GOOGLE_CSE_ID=
YOUTUBE_API_KEY=

# Optional image search
OPENVERSE_CLIENT_ID=
OPENVERSE_CLIENT_SECRET=

# Optional sports data
THESPORTSDB_KEY=123
Running the App Again Later
Whenever you open a new terminal:

Windows
PowerShell
cd Aetherscan
.venv\Scripts\Activate.ps1
py app.py
macOS / Linux
bash
cd Aetherscan
source .venv/bin/activate
python3 app.py
To stop the app, press Ctrl+C in the terminal.

Built-in Games
Open the games page here:

Text
http://127.0.0.1:5006/games
The app includes several built-in games such as:

Quantum Forge
Nebula Swarm
Siege Forge
Basketball Free Throw Pro
Moto Tracks
Word Guess Game
FC 26: Ultra Manager Pro
Troubleshooting
Missing module error
Make sure the virtual environment is active, then reinstall dependencies:

bash
python3 -m pip install -r requirements.txt python-dotenv
or on Windows:

PowerShell
py -m pip install -r requirements.txt python-dotenv
Desktop window does not open
AetherScan can still run as a web app. Open:

Text
http://127.0.0.1:5006
AI features unavailable
Add one of the following keys to .env and restart the app:

GEMINI_API_KEY
GROQ_API_KEY
ANTHROPIC_API_KEY
Movie search says it needs an API key
Add a TMDB_API_KEY to .env and restart the app.

Project Structure
Text
Aetherscan/
├── app.py
├── requirements.txt
├── .env.example.txt
├── README.md
├── LICENSE
├── Templates/
├── .gitignore
└── other project files
Security Notes
Never commit .env to GitHub
Never share API keys in screenshots, issues, or support chats
Use .env.example.txt to document config names without exposing secrets
If a key is exposed, revoke it immediately and create a replacement
License
This project is licensed under the GNU General Public License v3.0.

See LICENSE for details.

Contributing
Bug reports, feature requests, and improvements are welcome. Before opening an issue, please check whether it has already been reported and include your operating system, Python version, and the command you used.

AetherScan is a personal, privacy-focused search engine and desktop browser built with Python, Flask, and PyQt6.
