#!/usr/bin/env bash

# =============================================================================
# Variable declarations.
# =============================================================================
BIN_FILE="cti-honeypot"
BIN_DIR=""
CFG_SRC_FILE="default-config.xml"
CFG_DST_FILE="config.xml"
CFG_DIR=""
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
INSTALL_DIR="/opt/cti-honeypot"
USERNAME="honeypot"
SYSTEMD_CHECK_DIR="/run/systemd/system"
SYSTEMD_DIR="/etc/systemd/system"
SYSTEMD_UNIT="cti-honeypot.service"

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
    # Ensure the script is running as root.
    #
    if [ "$(id --user)" -ne 0 ]; then
        echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}This installation script must be run as root.${CLEAR}" 1>&2
        echo
        exit 1
    fi
}

# =============================================================================
# install_app:
# Executes the installation process. This includes:
#   1. Create the directory structure.
#   2. Copy the binary and default config to the installation directory.
#   3. Create a service account user for running the application.
#   4. Assign the user ownership and write permissions on the installation
#      directory.
#   5. Run setcap on the binary to allow the user to bind to ports < 1024.
#   6. Create a systemd service, start the service, and configure for automatic
#      startup.
# =============================================================================
install_app() {
    #
    # Locate the application's binary relative to the script's path.
    #
    if [ -f "${SCRIPT_DIR}/${BIN_FILE}" ]; then
        # Found in the same directory as the script.
        BIN_DIR="${SCRIPT_DIR}"
    else
        if [ -f "${SCRIPT_DIR}/../out/${BIN_FILE}" ]; then
            # Found in ../out relative to the script.
            BIN_DIR="${SCRIPT_DIR}/../out"
        else
            # Could not locate.
            echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Unable to locate the file: ${YELLOW}'${BIN_FILE}'${CLEAR}" 1>&2
            echo
            exit 1
        fi
    fi

    #
    # Locate the configuration file relative to the script's path.
    #
    if [ -f "${SCRIPT_DIR}/${CFG_SRC_FILE}" ]; then
        # Found in the same directory as the script.
        CFG_DIR="${SCRIPT_DIR}"
    else
        if [ -f "${SCRIPT_DIR}/../configs/${CFG_SRC_FILE}" ]; then
            # Found in ../configs relative to the script.
            CFG_DIR="${SCRIPT_DIR}/../configs"
        else
            # Could not locate.
            echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Unable to locate the file: ${YELLOW}'${CFG_SRC_FILE}'${CLEAR}" 1>&2
            echo
            exit 1
        fi
    fi

    #
    # Print install banner.
    #
    echo
    echo -e " ${WHITE}Installing CTI Honeypot${CLEAR}"
    echo -e " ${DGRAY}=======================${CLEAR}"
    echo
    echo -e " ${DGRAY}-  ${LGRAY}Installing to: ${CYAN}'${INSTALL_DIR}/'"

    #
    # Create the directory structure.
    #
    umask 002
    mkdir --parents "${INSTALL_DIR}/bin/" "${INSTALL_DIR}/var/log/" "${INSTALL_DIR}/etc/" "${INSTALL_DIR}/certs/"

    #
    # Copy the binary.
    #
    cp --force "${BIN_DIR}/${BIN_FILE}" "${INSTALL_DIR}/bin/"
    if [ $? -ne 0 ]; then
        echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Failed to copy file: ${YELLOW}'${BIN_DIR}/${BIN_FILE}' ${WHITE}to: ${YELLOW}'${INSTALL_DIR}/bin/'${CLEAR}" 1>&2
        echo
        exit 1
    fi

    #
    # Copy the configuration file, if it doesn't already exist.
    #
    if [ -f "${INSTALL_DIR}/etc/${CFG_DST_FILE}" ]; then
        # Don't copy anything. An existing configuration file already exists.
        echo -e " ${DGRAY}-  ${LGRAY}Keeping existing configuration found at: ${CYAN}'${INSTALL_DIR}/etc/${CFG_DST_FILE}'"
    else
        cp --force "${CFG_DIR}/${CFG_SRC_FILE}" "${INSTALL_DIR}/etc/${CFG_DST_FILE}"
        if [ $? -ne 0 ]; then
            echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Failed to copy file: ${YELLOW}'${CFG_DIR}/${CFG_SRC_FILE}' ${WHITE}to: ${YELLOW}'${INSTALL_DIR}/etc/${CFG_DST_FILE}'${CLEAR}" 1>&2
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
            echo -e "${DGRAY}[${RED}Error${DGRAY}] ${WHITE}Failed to create user: ${YELLOW}'${USERNAME}'${CLEAR}" 1>&2
            echo
            exit 1
        fi
    fi

    #
    # Set file and directory permissions.
    #
    echo -e " ${DGRAY}-  ${LGRAY}Setting file and directory permissions.${CLEAR}"
    chown --recursive "${USERNAME}":"${USERNAME}" "${INSTALL_DIR}"
    chmod 775 "${INSTALL_DIR}/bin/${BIN_FILE}"
    chmod 664 "${INSTALL_DIR}/etc/${CFG_DST_FILE}"

    #
    # Allow cti-honeypot to bind to a port < 1024 when running as a non-root user.
    #
    setcap cap_net_bind_service=+ep "${INSTALL_DIR}/bin/${BIN_FILE}"

    #
    # Detect the init system.
    #
    if [ -d "${SYSTEMD_CHECK_DIR}" ] && [ -d "${SYSTEMD_DIR}" ]; then
        #
        # Systemd init system detected.
        #
        local UNIT_FILE_FULL_PATH="${SYSTEMD_DIR}/${SYSTEMD_UNIT}"

        #
        # Create a systemd unit file.
        #
        echo -e " ${DGRAY}-  ${LGRAY}Creating service: ${CYAN}'${UNIT_FILE_FULL_PATH}'${CLEAR}"
        if [ ! -f "${UNIT_FILE_FULL_PATH}" ]; then
            cat > ${UNIT_FILE_FULL_PATH} << EOF
[Unit]
Description=CTI Honeypot
ConditionPathExists="${INSTALL_DIR}/bin/${BIN_FILE}"
After=network.target

[Service]
Type=simple
User=${USERNAME}
Group=${USERNAME}
Restart=on-failure
RestartSec=10
ExecStart="${INSTALL_DIR}/bin/${BIN_FILE}" -config "${INSTALL_DIR}/etc/${CFG_DST_FILE}"

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
        echo -e "${YELLOW} Check service status with: ${CYAN}systemctl status ${SYSTEMD_UNIT}${CLEAR}"
        echo -e "${YELLOW}       Logs are located at: ${CYAN}${INSTALL_DIR}/var/log/${CLEAR}"
        echo -e "${YELLOW}  Configuration file is at: ${CYAN}${INSTALL_DIR}/etc/${CFG_DST_FILE}${CLEAR}"
        echo
        echo

    else
        #
        # Unsupported init system detected. Skip service creation.
        #
        echo
        echo -e "${WHITE} Installation complete${BLUE}${CLEAR}"
        echo -e "${DGRAY} =====================${CLEAR}"
        echo
        echo -e "${YELLOW}       Logs are located at: ${CYAN}${INSTALL_DIR}/var/log/${CLEAR}"
        echo -e "${YELLOW}  Configuration file is at: ${CYAN}${INSTALL_DIR}/etc/${CFG_DST_FILE}${CLEAR}"
        echo
        echo
        echo -e " ${RED}Unsupported init system detected${CLEAR}"
        echo
        echo -e " ${WHITE}You can manually run CTI Honeypot using the following command:${CLEAR}"
        echo -e " ${GREEN}${INSTALL_DIR}/bin/${BIN_FILE} -config ${INSTALL_DIR}/etc/${CFG_DST_FILE}${CLEAR}"
        echo
        echo -e " ${LGRAY}If calling from a startup script, run as the user: ${CYAN}${USERNAME}${CLEAR}"
        echo -e " ${LGRAY}Otherwise, ensure you have write permissions on: ${CYAN}${INSTALL_DIR}/${CLEAR}"
        echo
        echo
    fi
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
    echo -e " ${WHITE}Unnstalling CTI Honeypot${CLEAR}"
    echo -e " ${DGRAY}========================${CLEAR}"
    echo

    #
    # Determine if the system has systemd.
    #
    if [ -d "${SYSTEMD_CHECK_DIR}" ] && [ -d "${SYSTEMD_DIR}" ]; then
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
    fi

    #
    # Delete the user, if it exists.
    #
    if id "${USERNAME}" &> /dev/null; then
        echo -e " ${DGRAY}-  ${LGRAY}Deleting user: ${CYAN}'${USERNAME}'${CLEAR}"
        userdel "${USERNAME}"
    else
        echo -e " ${RED}-  ${LGRAY}User ${WHITE}'${USERNAME}' ${LGRAY}does not exist. Skipping deletion."
    fi

    #
    # Delete the installation directory, if it exists.
    #
    if [ -d "${INSTALL_DIR}" ]; then
        echo -e " ${DGRAY}-  ${LGRAY}Deleting installation directory: ${CYAN}'${INSTALL_DIR}/'${CLEAR}"
        rm --recursive --force "${INSTALL_DIR}"
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
    echo -e " ${LGRAY}CTI Honeypot has been removed from your system.${CLEAR}"
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

    if [[ "$1" == "uninstall" ]]; then
        uninstall_app
        exit 0
    else
        install_app
        exit 0
    fi
}

# Script execution starts here by calling the main function.
main "$@"