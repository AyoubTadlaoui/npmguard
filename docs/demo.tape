# vhs tape for the npmguard demo GIF.
# Regenerate with: vhs docs/demo.tape
# Requires: vhs (https://github.com/charmbracelet/vhs)
#           and a `npmguard` binary on PATH (cargo build --release first).

Output docs/demo.gif

Set Shell zsh
Set FontSize 16
Set Width 1200
Set Height 760
Set Theme "Catppuccin Mocha"
Set Padding 24
Set TypingSpeed 55ms
Set PlaybackSpeed 1.0

# Prompt setup
Hide
Type "PS1='%F{8}$%f '" Enter
Type "clear" Enter
Show

# 1. A safe package: lodash
Type "npmguard check lodash" Sleep 400ms Enter
Sleep 3s

# 2. A typosquat that's in OSV's malware namespace.
Type "npmguard install lodahs" Sleep 400ms Enter
Sleep 4s

# Hold the final frame so viewers can read the block verdict.
Sleep 3s
