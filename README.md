# AetherScan

AetherScan is a personal, privacy-focused search engine and desktop browser built with Python, Flask, and PyQt6. Search the web, images, videos, news, sports, maps, and movies in one app. It also includes AI features, bookmarks, browsing history, tab groups, downloads, and seven built-in games.

> **Privacy note:** AetherScan does not depend on one search provider, but searches may be sent to services such as DuckDuckGo, Wikipedia, Openverse, Reddit, Stack Overflow, Hacker News, and other enabled APIs. Review each service's terms and privacy policies before using the app.

## Features

- Web search using several public sources
- Image, video, news, sports, map, and movie search
- Optional AI overviews and AI chat
- Optional TMDb movie information and watch-provider links
- Desktop browser window with tabs
- Bookmarks, history, downloads, tab groups, and session restore
- Seven built-in games at `/games`
- Works with no API keys for the core web search features

## Requirements

- Windows, macOS, or Linux
- Python 3.10 or newer recommended
- Internet connection
- Git, or a downloaded copy of this repository

## Quick setup on Windows

Open PowerShell in the folder where you want to install AetherScan and run:

```powershell
git clone https://github.com/worldcup2019/Aetherscan.git
cd Aetherscan

py -m venv .venv
.venv\Scripts\Activate.ps1

py -m pip install --upgrade pip
py -m pip install -r requirements.txt python-dotenv

Copy-Item .env.example.txt .env
py app.py
```

AetherScan normally opens in its desktop window. If it does not, open this address in a browser:

```text
http://127.0.0.1:5006
```

### If PowerShell blocks activation

You can either run the activation command with Command Prompt instead:

```bat
.venv\Scripts\activate.bat
```

Or allow locally created scripts for your user account in PowerShell:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate the environment again:

```powershell
.venv\Scripts\Activate.ps1
```

## Setup on macOS or Linux

```bash
git clone https://github.com/worldcup2019/Aetherscan.git
cd Aetherscan

python3 -m venv .venv
source .venv/bin/activate

python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt python-dotenv

cp .env.example.txt .env
python3 app.py
```

Open `http://127.0.0.1:5006` if the desktop window does not appear.

## API keys

API keys are optional. Core web search works without them, but keys enable additional features. Copy `.env.example.txt` to `.env` and add only the keys you want to use.

```dotenv
# Recommended for local development
SECRET_KEY=replace-this-with-a-long-random-string

# Choose an AI provider for AI Overview and AI Chat
GEMINI_API_KEY=
GROQ_API_KEY=
ANTHROPIC_API_KEY=

# Movie search
TMDB_API_KEY=

# 3D maps
CESIUM_ION_TOKEN=
```

Other optional variables in `.env.example.txt` enable additional search, image, video, and sports sources.

### Important security rules

- Never commit `.env` to GitHub.
- Never post API keys in screenshots, issues, or chat.
- Use `.env.example.txt` for sharing setting names without secret values.
- If a key is exposed, revoke it and create a replacement immediately.
- Use a strong random `SECRET_KEY` for any non-local deployment.

Signed-in users can also add supported personal keys from the AetherScan Settings page. Keys entered there are stored in the local SQLite accounts database, so only use this feature on a computer you trust.

## Running the application

Every time you open a new terminal:

```powershell
cd Aetherscan
.venv\Scripts\Activate.ps1
py app.py
```

To stop the application, return to the terminal and press `Ctrl+C`.

## Games

Open the built-in arcade at:

```text
http://127.0.0.1:5006/games
```

The current games include Quantum Forge, Nebula Swarm, Siege Forge, Basketball Free Throw Pro, Moto Tracks, Word Guess Game, and FC 26: Ultra Manager Pro.

## Troubleshooting

### `No module named ...`

Make sure the virtual environment is activated, then reinstall the dependencies:

```powershell
py -m pip install -r requirements.txt python-dotenv
```

### The desktop window does not open

AetherScan can still run as a Flask web app. Open:

```text
http://127.0.0.1:5006
```

### Movie search says it needs an API key

Add a `TMDB_API_KEY` in `.env`, save the file, and restart AetherScan. Movie search requires TMDb; ordinary web search does not.

### AI features are unavailable

Add `GEMINI_API_KEY`, `GROQ_API_KEY`, or another supported AI key to `.env`, then restart the app. AI features are optional.

## Project structure

```text
Aetherscan/
├── app.py                 # Main Flask and desktop application
├── requirements.txt       # Python dependencies
├── .env.example.txt       # Example configuration file
├── Templates/             # HTML templates and built-in games
└── .gitignore
```

## Contributing

Bug reports, ideas, and improvements are welcome. Before opening an issue, check whether it has already been reported and include your operating system, Python version, command used, and the complete error message. Do not include API keys or other secrets.

## License

AetherScan is available under the [MIT License](LICENSE). 
