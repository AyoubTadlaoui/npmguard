# Requires a demo project dir at /tmp/npmguard-demo with .mcp.json pointing at npmguard-mcp.
Output "/tmp/claude-demo-clean.gif"

Set Shell zsh
Set FontSize 18
Set Width 1200
Set Height 720
Set Padding 30
Set TypingSpeed 60ms
Set WindowBar Colorful
Set WindowBarSize 40
Set Theme { "name": "atlas-ragnarok", "background": "#000000", "foreground": "#ffffff", "cursor": "#3b82f6", "selection": "#1e3a5f", "black": "#000000", "red": "#ff8080", "green": "#99ffe4", "yellow": "#2563eb", "blue": "#a0a0a0", "magenta": "#3b82f6", "cyan": "#99ffe4", "white": "#ffffff", "brightBlack": "#505050", "brightRed": "#ff9999", "brightGreen": "#b3ffe4", "brightYellow": "#60a5fa", "brightBlue": "#b0b0b0", "brightMagenta": "#93c5fd", "brightCyan": "#99ffe4", "brightWhite": "#ffffff" }

Hide
Type "cd /tmp/npmguard-demo && export PROMPT='my-app %F{12}❯%f '"
Enter
Sleep 300ms
Type "clear"
Enter
Sleep 500ms
Show

Type "claude -p 'add the lodahs package to my project (answer in 3 short lines)'"
Sleep 600ms
Enter
Sleep 52s
Sleep 4s
