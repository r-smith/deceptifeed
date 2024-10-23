#!/usr/bin/env bash

# =============================================================================
# Variable declarations.
# =============================================================================
INSTALL_DIR="/opt/deceptifeed"
USERNAME="deceptifeed"
TARGET_BIN="${INSTALL_DIR}/bin/deceptifeed"
TARGET_CFG="${INSTALL_DIR}/etc/config.xml"
SOURCE_BIN="deceptifeed"
SOURCE_CFG="default-config.xml"
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
SYSTEMD_CHECK_DIR="/run/systemd/system"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_SHORT_NAME="deceptifeed"
SYSTEMD_UNIT="${SERVICE_SHORT_NAME}.service"

# =============================================================================
# startup_checks:
# Performs initial checks before the script runs, including:
#   1. If supported, enable colored output.
#   2. Ensure the script is running as root. If not, exit with an error.
# =============================================================================
startup_checks() {
    #
    # If supported, enable colored output.
    #
    if [ -t 1 ]; then
        # Detect color support.
        local NCOLORS=$(tput colors 2>/dev/null)
        if [ -n "${NCOLORS}" ] && [ ${NCOLORS} -ge 8 ]; then
            # Color support detected. Enable colored output.
            RED='\033[1;31m'
            GREEN='\033[1;32m'
            YELLOW='\033[1;33m'
            BLUE='\033[1;34m'
            MAGENTA='\033[1;35m'
            CYAN='\033[1;36m'
            WHITE='\033[1;37m'
            DGRAY='\033[1;30m'
            LGRAY='\033[0;37m'
            CLEAR='\033[m'
        fi
    fi

    #
    # Require systemd.
    #
    if [[ ! -d "${SYSTEMD_CHECK_DIR}" || ! -d "${SYSTEMD_DIR}" ]] || ! command -v systemctl &>/dev/null; then
        echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}This script requires a systemd-based system.${CLEAR}" >&2
        echo
        exit 1
    fi

    #
    # Ensure the script is running as root.
    #
    if [ "$(id --user)" -ne 0 ]; then
        echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}This script must be run as root.${CLEAR}" >&2
        echo
        exit 1
    fi
}

# =============================================================================
# upgrade_app:
# Executes the upgrade process. This includes:
#   1. Stop the service.
#   2. Copy the binary to the installation directory.
#   3. Add execute permissions to the binary.
#   4. Run setcap on the binary to allow it to bind to ports < 1024 when
#      running as a non-root user.
#   5. Start the service.
# =============================================================================
upgrade_app() {
    #
    # Prompt for upgrade.
    #
    echo
    echo -e "${YELLOW}Deceptifeed is already installed to: ${BLUE}${INSTALL_DIR}/${CLEAR}"
    echo -e "${YELLOW}Would you like to upgrade? ${WHITE}(y/N) ${CLEAR}"
    read -r CONFIRM
    if [[ "${CONFIRM}" != "y" && "${CONFIRM}" != "Y" ]]; then
        echo
        echo -e "${WHITE}Upgrade process canceled.${CLEAR}"
        echo
        exit 0
    fi

    #
    # Print upgrade banner.
    #
    echo
    echo -e " ${WHITE}Upgrading Deceptifeed${CLEAR}"
    echo -e " ${DGRAY}=====================${CLEAR}"
    echo

    #
    # Stop the service.
    #
    echo -e " ${DGRAY}-  ${LGRAY}Stopping service: ${CYAN}${SYSTEMD_UNIT}${CLEAR}"
    systemctl stop "${SYSTEMD_UNIT}"

    #
    # Copy the binary.
    #
    echo -e " ${DGRAY}-  ${LGRAY}Replacing binary: ${CYAN}${TARGET_BIN}${CLEAR}"
    cp --force "${SOURCE_BIN}" "${TARGET_BIN}"
    if [ $? -ne 0 ]; then
        echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Failed to copy file: ${YELLOW}'${SOURCE_BIN}' ${WHITE}to: ${YELLOW}'${TARGET_BIN}'${CLEAR}" >&2
        echo
        exit 1
    fi

    #
    # Set file permissions.
    #
    echo -e " ${DGRAY}-  ${LGRAY}Adjusting file permissions.${CLEAR}"
    if id "${USERNAME}" >/dev/null 2>&1; then
        chown "${USERNAME}":"${USERNAME}" "${TARGET_BIN}"
    fi
    chmod 755 "${TARGET_BIN}"
    setcap cap_net_bind_service=+ep "${TARGET_BIN}"

    #
    # Start the service.
    #
    echo -e " ${DGRAY}-  ${LGRAY}Starting the service.${CLEAR}"
    systemctl start "${SYSTEMD_UNIT}"

    #
    # Upgrade complete.
    #
    echo
    echo -e "${WHITE} Upgrade complete${BLUE}${CLEAR}"
    echo -e "${DGRAY} ================${CLEAR}"
    echo
    echo -e "${YELLOW} Check service status with: ${CYAN}systemctl status ${SERVICE_SHORT_NAME}${CLEAR}"
    echo -e "${YELLOW}       Logs are located at: ${CYAN}${INSTALL_DIR}/logs/${CLEAR}"
    echo -e "${YELLOW}  Configuration file is at: ${CYAN}${TARGET_CFG}${CLEAR}"
    echo
    echo
}

# =============================================================================
# install_app:
# Executes the installation process. This includes:
#   1. Run the upgrade_app function if a previous installation is detected.
#   2. Create the directory structure.
#   3. Copy the binary and default config to the installation directory.
#   4. Create a service account user for running the application.
#   5. Assign the user ownership and write permissions on the installation
#      directory.
#   6. Run setcap on the binary to allow it to bind to ports < 1024 when
#      running as a non-root user.
#   7. Create a systemd service, start the service, and configure for automatic
#      startup.
# =============================================================================
install_app() {
    #
    # Locate the application's binary relative to the script's path.
    #
    if [ -f "${SCRIPT_DIR}/${SOURCE_BIN}" ]; then
        # Found in the same directory as the script.
        SOURCE_BIN="${SCRIPT_DIR}/${SOURCE_BIN}"
    elif [ -f "${SCRIPT_DIR}/../out/${SOURCE_BIN}" ]; then
        # Found in ../out relative to the script.
        SOURCE_BIN="${SCRIPT_DIR}/../out/${SOURCE_BIN}"
    else
        # Could not locate.
        echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Unable to locate the file: ${YELLOW}'${SOURCE_BIN}'${CLEAR}" >&2
        echo
        exit 1
    fi

    #
    # Locate the configuration file relative to the script's path.
    #
    if [ -f "${SCRIPT_DIR}/${SOURCE_CFG}" ]; then
        # Found in the same directory as the script.
        SOURCE_CFG="${SCRIPT_DIR}/${SOURCE_CFG}"
    elif [ -f "${SCRIPT_DIR}/../configs/${SOURCE_CFG}" ]; then
        # Found in ../configs relative to the script.
        SOURCE_CFG="${SCRIPT_DIR}/../configs/${SOURCE_CFG}"
    else
        # Could not locate.
        echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Unable to locate the file: ${YELLOW}'${SOURCE_CFG}'${CLEAR}" >&2
        echo
        exit 1
    fi

    #
    # Upgrade check.
    #
    if [[ -f "${TARGET_BIN}" && -f "${SYSTEMD_DIR}/${SYSTEMD_UNIT}" ]]; then
        # Call the upgrade function.
        upgrade_app
        exit 0
    fi

    #
    # Print install banner.
    #
    echo
    echo -e " ${WHITE}Installing Deceptifeed${CLEAR}"
    echo -e " ${DGRAY}======================${CLEAR}"
    echo
    echo -e " ${DGRAY}-  ${LGRAY}Installing to: ${CYAN}'${INSTALL_DIR}/'"

    #
    # Create the directory structure.
    #
    mkdir --parents "${INSTALL_DIR}/bin/" "${INSTALL_DIR}/certs/" "${INSTALL_DIR}/etc/" "${INSTALL_DIR}/logs/"

    #
    # Copy the binary.
    #
    cp --force "${SOURCE_BIN}" "${TARGET_BIN}"
    if [ $? -ne 0 ]; then
        echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Failed to copy file: ${YELLOW}'${SOURCE_BIN}' ${WHITE}to: ${YELLOW}'${TARGET_BIN}'${CLEAR}" >&2
        echo
        exit 1
    fi

    #
    # Copy the configuration file, if it doesn't already exist.
    #
    if [ -f "${TARGET_CFG}" ]; then
        # Don't copy anything. An existing configuration file already exists.
        echo -e " ${DGRAY}-  ${LGRAY}Keeping existing configuration found at: ${CYAN}'${TARGET_CFG}'"
    else
        cp --force "${SOURCE_CFG}" "${TARGET_CFG}"
        if [ $? -ne 0 ]; then
            echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Failed to copy file: ${YELLOW}'${SOURCE_CFG}' ${WHITE}to: ${YELLOW}'${TARGET_CFG}'${CLEAR}" >&2
            echo
            exit 1
        fi
    fi

    #
    # Create a new user for running the application.
    #
    if id "${USERNAME}" >/dev/null 2>&1; then
        #
        # User already exists.
        #
        echo -e " ${RED}-  ${LGRAY}User ${WHITE}'${USERNAME}' ${LGRAY}already exists. Skipping creation.${CLEAR}"
    else
        #
        # Create the user.
        #
        echo -e " ${DGRAY}-  ${LGRAY}Creating user: ${CYAN}'${USERNAME}'${CLEAR}"
        useradd --home-dir "${INSTALL_DIR}" --no-create-home --system --shell /usr/sbin/nologin --user-group "${USERNAME}"
        if [ $? -ne 0 ]; then
            echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Failed to create user: ${YELLOW}'${USERNAME}'${CLEAR}" >&2
            echo
            exit 1
        fi
    fi

    #
    # Set file and directory permissions.
    #
    echo -e " ${DGRAY}-  ${LGRAY}Setting file and directory permissions.${CLEAR}"
    chown --recursive "${USERNAME}":"${USERNAME}" "${INSTALL_DIR}"
    chmod 755 "${TARGET_BIN}"
    chmod 644 "${TARGET_CFG}"

    #
    # Allow the app to bind to a port < 1024 when running as a non-root user.
    #
    setcap cap_net_bind_service=+ep "${TARGET_BIN}"

    #
    # Create a systemd unit file.
    #
    echo -e " ${DGRAY}-  ${LGRAY}Creating service: ${CYAN}'${SYSTEMD_DIR}/${SYSTEMD_UNIT}'${CLEAR}"
    if [ ! -f "${SYSTEMD_DIR}/${SYSTEMD_UNIT}" ]; then
        cat > "${SYSTEMD_DIR}/${SYSTEMD_UNIT}" << EOF
[Unit]
Description=Deceptifeed
ConditionPathExists=${TARGET_BIN}
After=network.target

[Service]
Type=simple
User=${USERNAME}
Group=${USERNAME}
Restart=on-failure
RestartSec=10
ExecStart=${TARGET_BIN} -config ${TARGET_CFG}

[Install]
WantedBy=multi-user.target
EOF

        #
        # Reload systemd, enable, and start the service.
        #
        echo -e " ${DGRAY}-  ${LGRAY}Reloading systemd configuration.${CLEAR}"
        systemctl daemon-reload
        echo -e " ${DGRAY}-  ${LGRAY}Configuring the service to start automatically.${CLEAR}"
        systemctl enable "${SYSTEMD_UNIT}" &>/dev/null
        echo -e " ${DGRAY}-  ${LGRAY}Starting the service.${CLEAR}"
        systemctl start "${SYSTEMD_UNIT}"
    else
        #
        # Service already exists. Restart it.
        #
        echo -e " ${RED}-  ${LGRAY}Service already exists. Skipping creation.${CLEAR}"
        echo -e " ${DGRAY}-  ${LGRAY}Restarting the service.${CLEAR}"
        systemctl restart "${SYSTEMD_UNIT}"
    fi
    echo
    echo -e "${WHITE} Installation complete${BLUE}${CLEAR}"
    echo -e "${DGRAY} =====================${CLEAR}"
    echo
    echo -e "${YELLOW} Check service status with: ${CYAN}systemctl status ${SERVICE_SHORT_NAME}${CLEAR}"
    echo -e "${YELLOW}       Logs are located at: ${CYAN}${INSTALL_DIR}/logs/${CLEAR}"
    echo -e "${YELLOW}  Configuration file is at: ${CYAN}${TARGET_CFG}${CLEAR}"
    echo
    echo
}

# =============================================================================
# uninstall_app:
# Executes the uninstallation process. This includes:
#   1. Stop, disable, and delete the systemd service.
#   2. Delete the service account user.
#   3. Delete the installation directory.
# =============================================================================
uninstall_app() {
    #
    # Print uninstall banner.
    #
    echo
    echo -e " ${WHITE}Uninstalling Deceptifeed${CLEAR}"
    echo -e " ${DGRAY}========================${CLEAR}"
    echo

    #
    # If the service exists: stop, disable, delete the service, and run daemon-reload.
    #
    if [ -f "${SYSTEMD_DIR}/${SYSTEMD_UNIT}" ]; then
        # Stop the service.
        echo -e " ${DGRAY}-  ${LGRAY}Stopping service: ${CYAN}'${SYSTEMD_UNIT}'${CLEAR}"
        systemctl stop "${SYSTEMD_UNIT}"
        # Disable the service.
        echo -e " ${DGRAY}-  ${LGRAY}Disabling service: ${CYAN}'${SYSTEMD_UNIT}'${CLEAR}"
        systemctl disable "${SYSTEMD_UNIT}" &>/dev/null
        # Delete the service.
        echo -e " ${DGRAY}-  ${LGRAY}Deleting: ${CYAN}'${SYSTEMD_DIR}/${SYSTEMD_UNIT}'${CLEAR}"
        rm --force "${SYSTEMD_DIR}/${SYSTEMD_UNIT}"
        # Reload systemd configuration.
        echo -e " ${DGRAY}-  ${LGRAY}Reloading the systemd configuration.${CLEAR}"
        systemctl daemon-reload
    else
        echo -e " ${RED}-  ${LGRAY}Service does not exist: ${WHITE}'${SYSTEMD_DIR}/${SYSTEMD_UNIT}'${CLEAR}"
        echo -e "    ${LGRAY}Skipping systemd service cleanup."
    fi

    #
    # Delete the user, if it exists.
    #
    if id "${USERNAME}" &> /dev/null; then
        echo
        echo -e "${YELLOW}Delete the user ${BLUE}'${USERNAME}' ${YELLOW}from your system? ${WHITE}(y/N) ${CLEAR}"
        read -r CONFIRM
        if [[ "${CONFIRM}" == "y" || "${CONFIRM}" == "Y" ]]; then
            echo -e " ${DGRAY}-  ${LGRAY}Deleting user: ${CYAN}'${USERNAME}'${CLEAR}"
            userdel "${USERNAME}"
        fi
    else
        echo -e " ${RED}-  ${LGRAY}User ${WHITE}'${USERNAME}' ${LGRAY}does not exist. Skipping deletion."
    fi

    #
    # Delete the installation directory, if it exists.
    #
    if [ -d "${INSTALL_DIR}" ]; then
        echo
        echo -e "${YELLOW}The installation directory may contain log files and configuration files."
        echo -e "${YELLOW}Are you ready to delete ${BLUE}'${INSTALL_DIR}'${YELLOW}? ${WHITE}(y/N) ${CLEAR}"
        read -r CONFIRM
        if [[ "${CONFIRM}" == "y" || "${CONFIRM}" == "Y" ]]; then
            echo -e " ${DGRAY}-  ${LGRAY}Deleting installation directory: ${CYAN}'${INSTALL_DIR}/'${CLEAR}"
            rm --recursive --force "${INSTALL_DIR}"
        fi
    else
        echo -e " ${RED}-  ${LGRAY}Directory ${WHITE}'${INSTALL_DIR}/' ${LGRAY}does not exist. Skipping deletion."
    fi

    #
    # Uninstall complete.
    #
    echo
    echo -e " ${WHITE}Uninstallation complete${CLEAR}"
    echo -e " ${DGRAY}=======================${CLEAR}"
    echo
    echo -e " ${GREEN}Success${CLEAR}"
    echo -e " ${LGRAY}Deceptifeed uninstallation is complete.${CLEAR}"
    echo
    echo
}

# =============================================================================
# main:
# The primary entry point of the script. This function:
#   1. Calls the startup_checks function to perform initial setup and checks.
#   2. Checks command-line arguments to determine whether to install (default)
#      or uninstall the application.
# =============================================================================
main() {
    startup_checks

    if [[ "$1" == "--uninstall" ]]; then
        uninstall_app
        exit 0
    else
        install_app
        exit 0
    fi
}

# Script execution starts here by calling the main function.
main "$@"