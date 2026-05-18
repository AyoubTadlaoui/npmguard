# vhs tape for the npmguard demo GIF.
# Regenerate with: PATH="$PWD/target/release:$PATH" vhs docs/demo.tape
# Requires: vhs (https://github.com/charmbracelet/vhs) and `cargo build --release`.

Output docs/demo.gif

Set Shell zsh
Set FontSize 17
Set Width 1180
Set Height 540
Set Padding 28
Set TypingSpeed 45ms

# atlas-ragnarok palette — pure black background, thunder-blue cursor,
# peppermint accents, crimson for errors/block.
# https://github.com/AyoubTadlaoui/atlas-ragnarok
Set Theme { "name": "atlas-ragnarok", "background": "#000000", "foreground": "#ffffff", "cursor": "#3b82f6", "selection": "#1e3a5f", "black": "#000000", "red": "#ff8080", "green": "#99ffe4", "yellow": "#2563eb", "blue": "#a0a0a0", "magenta": "#3b82f6", "cyan": "#99ffe4", "white": "#ffffff", "brightBlack": "#505050", "brightRed": "#ff9999", "brightGreen": "#b3ffe4", "brightYellow": "#60a5fa", "brightBlue": "#b0b0b0", "brightMagenta": "#93c5fd", "brightCyan": "#99ffe4", "brightWhite": "#ffffff" }

# Prepare a minimal prompt and pre-run the "safe" check off-camera so that
# even the very first visible frame shows real content (lodash → ok), then
# the recording proceeds with the dramatic block on lodahs.
Hide
Type "PROMPT='%F{8}$%f '" Enter
Sleep 200ms
Type "clear" Enter
Sleep 200ms
Type "npmguard check lodash" Enter
Sleep 2200ms
Show

# Now visible: the typosquat that gets blocked.
Type "npmguard install lodahs" Sleep 300ms Enter
Sleep 4500ms

# Hold the block frame so viewers can read all three signals.
Sleep 2500ms
