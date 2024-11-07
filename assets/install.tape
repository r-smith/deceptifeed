# ==============================================================================
# install.tape:
# Generate a GIF of the Deceptifeed installation process using Charm's VHS
#
# - VHS is available here: https://github.com/charmbracelet/vhs
#
# Notes:
# - Build using: `vhs install.tape`
# - Built with VHS version 0.8.0.
# - Since this tape file performs the installation process, Deceptifeed must not
#   be installed.
# - To avoid password prompts for `sudo` commands, temporarily disable `sudo`
#   password requirements for your user:
#   - Run `visudo`
#   - Add the following line, replacing `username` with the name of the user
#     that runs VHS: `username ALL=(ALL) NOPASSWD:ALL`
# ==============================================================================

# =====
# Setup
# =====
Output install.gif

Set FontSize 16
Set Width 735
Set Height 509
Set Padding 50
Set PlaybackSpeed 1.1
Set LoopOffset 80%
Set Theme { "name": "CGA Custom", "black": "#000000", "red": "#aa0000", "green": "#00aa00", "yellow": "#aa5500", "blue": "#0000aa", "magenta": "#aa00aa", "cyan": "#00aaaa", "white": "#aaaaaa", "brightBlack": "#555555", "brightRed": "#EF2929", "brightGreen": "#55ff55", "brightYellow": "#FCE94F", "brightBlue": "#5555ff", "brightMagenta": "#ff55ff", "brightCyan": "#55ffff", "brightWhite": "#ffffff", "background": "#000000", "foreground": "#aaaaaa", "cursor": "#b8b8b8", "selection": "#c1deff" }

# ====
# Hide
# ====
# Download the Deceptifeed package.
Hide
  Type    "wget https://github.com/r-smith/deceptifeed/releases/download/v0.9.0/deceptifeed_0.9.0_linux_amd64.tar.gz"
  Enter   Sleep 10s 
  Ctrl+L  Sleep 0.5s
Show

# ====
# Show
# ====
# Extract the files.
Type   "tar xvzf deceptifeed_0.9.0_linux_amd64.tar.gz"  Sleep 1s
Enter  Sleep 1s

# Enter the extracted directory.
Type   "cd deceptifeed"  Sleep 1s
Enter  Sleep 1s

# Run the installation script, then an extended pause to showcase the output.
Type   "sudo ./install.sh"  Sleep 1s
Enter  Sleep 18s

# ====
# Hide
# ====
# Uninstall and cleanup.
Hide
  Type  "sudo ./install.sh --uninstall"  Enter Sleep 5s
  Type  "yes"  Enter  Sleep 3s
  Type  "cd .."  Enter
  Type  "rm -rf deceptifeed deceptifeed_0.9.0_linux_amd64.tar.gz"  Enter