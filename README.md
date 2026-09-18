# AetherScan

AetherScan is a privacy-focused personal search engine and desktop browser built with Python, Flask, and PyQt6. It brings web search, media search, bookmarks, browser tabs, downloads, AI features, and built-in games together in one application.

Search the web, images, videos, news, sports, maps, movies, and more without being locked into a single provider.

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
- Python 3.10 or newer
- Visual Studio Code (recommended for development)
- Git, or a downloaded copy of the repository
- An internet connection

## Set Up AetherScan in Visual Studio Code

The commands below are run in the **VS Code integrated terminal**. Open the terminal with **Terminal > New Terminal** or press `` Ctrl+` ``.

### 1. Clone and open the project

```bash
git clone https://github.com/worldcup2019/Aetherscan.git
cd Aetherscan
code .
```

If `code .` is not available, open VS Code manually and choose **File > Open Folder**, then select the `Aetherscan` folder.

### 2. Create a virtual environment

#### Windows PowerShell

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run this once in the VS Code terminal:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

Then activate the environment again:

```powershell
.venv\Scripts\Activate.ps1
```

#### macOS or Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
```

When the environment is active, `(.venv)` appears at the beginning of the terminal prompt.

### 3. Install dependencies

Run the command for your operating system:

#### Windows PowerShell

```powershell
py -m pip install --upgrade pip
py -m pip install -r requirements.txt python-dotenv
```

#### macOS or Linux

```bash
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt python-dotenv
```

### 4. Create the environment file

#### Windows PowerShell

```powershell
Copy-Item .env.example.txt .env
```

#### macOS or Linux

```bash
cp .env.example.txt .env
```

Open `.env` in VS Code and set a secret key:

```env
SECRET_KEY=change-this-to-a-long-random-string
```

The other API keys are optional. AetherScan's core search features can run without them.

### 5. Start the web application

Run this in the VS Code terminal:

#### Windows PowerShell

```powershell
py app.py
```

#### macOS or Linux

```bash
python3 app.py
```

Then open this address in your web browser:

<http://127.0.0.1:5006>

Keep the VS Code terminal running while you use the application. To stop it, press **Ctrl+C**.

## Running AetherScan Again Later

Open the AetherScan folder in VS Code, open a new terminal, activate the virtual environment, and start the app.

### Windows PowerShell

```powershell
cd Aetherscan
.venv\Scripts\Activate.ps1
py app.py
```

### macOS or Linux

```bash
cd Aetherscan
source .venv/bin/activate
python3 app.py
```

After starting the app, visit <http://127.0.0.1:5006>.

## Optional Environment Variables

The project includes `.env.example.txt`. Copy it to `.env` and add only the keys you want to use.

```env
# Required for real sessions/logins in production
SECRET_KEY=change-this-to-a-long-random-string

# AI Overview and AI Chat (optional)
GEMINI_API_KEY=
GEMINI_MODEL=gemini-3.8-flash
ANTHROPIC_API_KEY=
ANTHROPIC_MODEL=claude-sonnet-5
GROQ_API_KEY=
GROQ_MODEL=llama-3.3-70b-versatile

# Movies tab (optional)
TMDB_API_KEY=

# Maps tab and 3D globe (optional)
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
```

## Built-in Games

Open the games page at <http://127.0.0.1:5006/games>.

The app includes games such as:

- Quantum Forge
- Nebula Swarm
- Siege Forge
- Basketball Free Throw Pro
- Moto Tracks
- Word Guess Game
- FC 26: Ultra Manager Pro

## Troubleshooting

### Missing module error

Make sure `.venv` is active in the VS Code terminal, then reinstall the dependencies.

Windows PowerShell:

```powershell
py -m pip install -r requirements.txt python-dotenv
```

macOS or Linux:

```bash
python3 -m pip install -r requirements.txt python-dotenv
```

### The desktop window does not open

The Flask web application can still run without the desktop window. Start the app from the VS Code terminal and open:

<http://127.0.0.1:5006>

### AI features are unavailable

Add one of these keys to `.env`, then restart AetherScan:

- `GEMINI_API_KEY`
- `GROQ_API_KEY`
- `ANTHROPIC_API_KEY`

### Movie search says that an API key is required

Add `TMDB_API_KEY` to `.env`, then restart the app.

### Port 5006 is already in use

Stop the other AetherScan process with **Ctrl+C**, or close the application that is using port 5006 before starting AetherScan again.

## Project Structure

```text
Aetherscan/
├── app.py
├── requirements.txt
├── .env.example.txt
├── README.md
├── LICENSE
├── Templates/
├── .gitignore
└── other project files
```

## Security Notes

- Never commit `.env` to GitHub.
- Never share API keys in screenshots, issues, or support chats.
- Use `.env.example.txt` to document configuration names without exposing secrets.
- If a key is exposed, revoke it immediately and create a replacement.

## License

This project is licensed under the GNU General Public License v3.0. See [LICENSE](LICENSE) for details.

## Contributing

Bug reports, feature requests, and improvements are welcome. Before opening an issue, check whether it has already been reported and include your operating system, Python version, and the command you used.
