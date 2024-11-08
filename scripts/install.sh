#!/usr/bin/env bash

# =============================================================================
# Variables.
# =============================================================================
install_dir="/opt/deceptifeed"
username="deceptifeed"
target_bin="${install_dir}/bin/deceptifeed"
target_cfg="${install_dir}/etc/config.xml"
source_bin="deceptifeed"
source_cfg="default-config.xml"
script_dir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
systemd_check_dir="/run/systemd/system"
systemd_dir="/etc/systemd/system"
service_short_name="deceptifeed"
systemd_unit="${service_short_name}.service"
auto_confirm_prompts=false

# =============================================================================
# startup_checks:
# Performs initial checks before the script runs, including:
#   1. If supported, enable colored output.
#   2. Ensure the script is running as root. If not, exit with an error.
# =============================================================================
startup_checks() {
    # If supported, enable colored output.
    if [[ -t 1 ]]; then
        n_colors=$(tput colors 2>/dev/null)
        if [[ -n "${n_colors}" ]] && [[ "${n_colors}" -ge 8 ]]; then
            red='\033[1;31m'
            green='\033[1;32m'
            yellow='\033[1;33m'
            blue='\033[1;34m'
            magenta='\033[1;35m'
            cyan='\033[1;36m'
            white='\033[1;37m'
            gray='\033[0;37m'
            dgray='\033[1;30m'
            clear='\033[m'
        fi
    fi

    # Output helper messages.
    msg_error="${dgray}[${red}Error${dgray}]${clear}"
    msg_info="${dgray}${magenta}‣${dgray}${clear}"

    # Require systemd.
    if [[ ! -d "${systemd_check_dir}" || ! -d "${systemd_dir}" ]] || ! command -v systemctl &>/dev/null; then
        echo -e "\n${msg_error} ${white}This script requires a systemd-based system.${clear}\n" >&2
        exit 1
    fi

    # Require root privileges.
    if [[ "$(id --user)" -ne 0 ]]; then
        echo -e "\n${msg_error} ${white}This script must be run as root.${clear}\n" >&2
        exit 1
    fi
}

# =============================================================================
# print_logo:
# Prints the application's logo.
# =============================================================================
print_logo() {
    echo -e "${red}         __                     __  _ ${yellow}______              __"
    echo -e "${red}    ____/ /__  ________  ____  / /_(_)${yellow} ____/__  ___  ____/ /"
    echo -e "${red}   / __  / _ \/ ___/ _ \/ __ \/ __/ /${yellow} /_  / _ \/ _ \/ __  /"
    echo -e "${red}  / /_/ /  __/ /__/  __/ /_/ / /_/ /${yellow} __/ /  __/  __/ /_/ /"
    echo -e "${red}  \____/\___/\___/\___/ .___/\__/_/${yellow}_/    \___/\___/\____/"
    echo -e "${blue}  ═══════════════════${red}/_/${blue}══════════════════════════════════"
    echo -e "${clear}\n"
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
    # Prompt for upgrade.
    echo
    echo -e " ${red}Deceptifeed is already installed to${gray}: ${blue}${install_dir}/${clear}"
    echo -e " ${red}Would you like to upgrade?${clear}"
    echo -en " ${gray}(${white}yes${gray}/${white}no${gray}) ${gray}[${yellow}no${gray}]${white}: ${green}"
    if [[ "${auto_confirm_prompts}" = true ]]; then
        echo "yes"
        response="yes"
    else
        read -r response
    fi
    echo -en "${clear}"
    if [[ ! "${response}" =~ ^[yY][eE][sS]$ && ! "${response}" =~ ^[yY]$ ]]; then
        echo -e "\n ${white}Upgrade canceled${clear}\n\n"
        exit 0
    fi

    # Print the application logo.
    print_logo

    # Stop the service.
    echo -e " ${msg_info}  ${gray}Stopping service: ${cyan}${systemd_unit}${clear}"
    systemctl stop "${systemd_unit}"

    # Backup (rename) the original binary.
    echo -e " ${msg_info}  ${gray}Moving old binary to: ${cyan}${target_bin}.bak${clear}"
    if ! mv -f "${target_bin}" "${target_bin}.bak"; then
        echo -e " ${msg_error} ${white}Failed to move file: ${yellow}'${target_bin}' ${white}to: ${yellow}'${target_bin}.bak'${clear}\n" >&2
        exit 1
    fi

    # Copy the binary.
    echo -e " ${msg_info}  ${gray}Replacing binary: ${cyan}${target_bin}${clear}"
    if ! cp --force "${source_bin}" "${target_bin}"; then
        echo -e " ${msg_error} ${white}Failed to copy file: ${yellow}'${source_bin}' ${white}to: ${yellow}'${target_bin}'${clear}\n" >&2
        exit 1
    fi

    # Set file permissions.
    if id "${username}" >/dev/null 2>&1; then
        chown "${username}":"${username}" "${target_bin}"
    fi
    chmod 755 "${target_bin}"
    setcap cap_net_bind_service=+ep "${target_bin}"

    # Start the service.
    echo -e " ${msg_info}  ${gray}Starting the service.${clear}"
    systemctl start "${systemd_unit}"

    # Upgrade complete.
    echo
    echo -e " ${green}✓  ${white}Upgrade complete${clear}\n"
    echo -e "${yellow} Check service status: ${cyan}systemctl status ${service_short_name}${clear}"
    echo -e "${yellow}         Log location: ${cyan}${install_dir}/logs/${clear}"
    echo -e "${yellow}   Configuration file: ${cyan}${target_cfg}${clear}\n\n"
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
    # Locate the application's binary relative to the script's path.
    if [[ -f "${script_dir}/${source_bin}" ]]; then
        # Found in the same directory as the script.
        source_bin="${script_dir}/${source_bin}"
    elif [[ -f "${script_dir}/../out/${source_bin}" ]]; then
        # Found in ../out relative to the script.
        source_bin="${script_dir}/../out/${source_bin}"
    else
        # Could not locate.
        echo -e "${msg_error} ${white}Unable to locate the file: ${yellow}'${source_bin}'${clear}\n" >&2
        exit 1
    fi

    # Locate the configuration file relative to the script's path.
    if [[ -f "${script_dir}/${source_cfg}" ]]; then
        # Found in the same directory as the script.
        source_cfg="${script_dir}/${source_cfg}"
    elif [[ -f "${script_dir}/../configs/${source_cfg}" ]]; then
        # Found in ../configs relative to the script.
        source_cfg="${script_dir}/../configs/${source_cfg}"
    else
        # Could not locate.
        echo -e "${msg_error} ${white}Unable to locate the file: ${yellow}'${source_cfg}'${clear}\n" >&2
        exit 1
    fi

    # Upgrade check.
    if [[ -f "${target_bin}" && -f "${systemd_dir}/${systemd_unit}" ]]; then
        upgrade_app
        exit 0
    fi

    # Print the application logo.
    print_logo
    echo -e " ${msg_info}  ${gray}Installing to: ${cyan}${install_dir}/"

    # Create the directory structure.
    mkdir --parents "${install_dir}/bin/" "${install_dir}/certs/" "${install_dir}/etc/" "${install_dir}/logs/"

    # Copy the binary.
    if ! cp --force "${source_bin}" "${target_bin}"; then
        echo -e " ${msg_error} ${white}Failed to copy file: ${yellow}'${source_bin}' ${white}to: ${yellow}'${target_bin}'${clear}\n" >&2
        exit 1
    fi

    # Copy the configuration file, if it doesn't already exist.
    if [[ -f "${target_cfg}" ]]; then
        # Don't copy anything. An existing configuration file already exists.
        echo -e " ${msg_info}  ${gray}Keeping existing configuration found at: ${cyan}${target_cfg}"
    else
        if ! cp --force "${source_cfg}" "${target_cfg}"; then
            echo -e " ${msg_error} ${white}Failed to copy file: ${yellow}'${source_cfg}' ${white}to: ${yellow}'${target_cfg}'${clear}\n" >&2
            exit 1
        fi
    fi

    # Create a new user for running the application.
    if id "${username}" >/dev/null 2>&1; then
        # User already exists.
        echo -e " ${msg_info}  ${gray}User ${white}'${username}' ${gray}already exists. Skipping creation.${clear}"
    else
        # Create the user.
        echo -e " ${msg_info}  ${gray}Creating user: ${cyan}${username}${clear}"
        if ! useradd --home-dir "${install_dir}" \
                     --no-create-home \
                     --system \
                     --shell /usr/sbin/nologin \
                     --user-group "${username}"; then
            echo -e " ${msg_error} ${white}Failed to create user: ${yellow}${username}${clear}\n" >&2
            exit 1
        fi
    fi

    # Set file and directory permissions.
    echo -e " ${msg_info}  ${gray}Setting file and directory permissions.${clear}"
    chown --recursive "${username}":"${username}" "${install_dir}"
    chmod 755 "${target_bin}"
    chmod 644 "${target_cfg}"

    # Allow the app to bind to a port < 1024 when running as a non-root user.
    setcap cap_net_bind_service=+ep "${target_bin}"

    # Create a systemd unit file.
    echo -e " ${msg_info}  ${gray}Creating service: ${cyan}${systemd_dir}/${systemd_unit}${clear}"
    cat > "${systemd_dir}/${systemd_unit}" << EOF
[Unit]
Description=Deceptifeed
ConditionPathExists=${target_bin}
After=network.target

[Service]
Type=simple
User=${username}
Group=${username}
Restart=on-failure
RestartSec=10
ExecStart=${target_bin} -config ${target_cfg}

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd, enable, and start the service.
    systemctl daemon-reload
    systemctl enable "${systemd_unit}" &>/dev/null
    systemctl start "${systemd_unit}"

    # Installation complete.
    echo
    echo -e " ${green}✓  ${white}Installation complete${clear}\n"
    echo -e "${yellow} Check service status: ${cyan}systemctl status ${service_short_name}${clear}"
    echo -e "${yellow}         Log location: ${cyan}${install_dir}/logs/${clear}"
    echo -e "${yellow}   Configuration file: ${cyan}${target_cfg}${clear}\n\n"
}

# =============================================================================
# uninstall_app:
# Executes the uninstallation process. This includes:
#   1. Stop, disable, and delete the systemd service.
#   2. Delete the service account user.
#   3. Delete the installation directory.
# =============================================================================
uninstall_app() {
    # Print uninstall banner.
    echo -e "\n ${white}Uninstalling Deceptifeed${clear}"
    echo -e " ${dgray}========================${clear}\n"

    # If the service exists: stop, disable, delete the service, and run daemon-reload.
    if [[ -f "${systemd_dir}/${systemd_unit}" ]]; then
        echo -e " ${msg_info}  ${gray}Stopping service: ${cyan}${systemd_unit}${clear}"
        systemctl stop "${systemd_unit}"
        echo -e " ${msg_info}  ${gray}Disabling service: ${cyan}${systemd_unit}${clear}"
        systemctl disable "${systemd_unit}" &>/dev/null
        echo -e " ${msg_info}  ${gray}Deleting: ${cyan}${systemd_dir}/${systemd_unit}${clear}"
        rm --force "${systemd_dir}/${systemd_unit}"
        echo -e " ${msg_info}  ${gray}Reloading the systemd configuration.${clear}"
        systemctl daemon-reload
    else
        echo -e " ${msg_info}  ${gray}Service does not exist: ${white}${systemd_dir}/${systemd_unit}${clear}"
        echo -e " ${msg_info}  ${gray}Skipping systemd service cleanup."
    fi

    # Delete the user, if it exists.
    if id "${username}" &> /dev/null; then
        echo -e " ${msg_info}  ${gray}Deleting user: ${cyan}${username}${clear}"
        userdel "${username}"
    else
        echo -e " ${msg_info}  ${gray}User ${white}'${username}' ${gray}does not exist. Skipping deletion."
    fi

    # Delete the installation directory, if it exists.
    if [[ -d "${install_dir}" ]]; then
        # Directory exists. Prompt for comfirmation to delete.
        echo
        echo -e " ${red}The installation directory may contain logs and configuration files."
        echo -e " ${red}Are you ready to delete ${blue}'${install_dir}'${red}?${clear}"
        echo -en " ${gray}(${white}yes${gray}/${white}no${gray}) ${gray}[${yellow}no${gray}]${white}: ${green}"
        if [[ "${auto_confirm_prompts}" = true ]]; then
            echo "yes"
            response="yes"
        else
            read -r response
        fi
        echo -en "${clear}"
        if [[ "${response}" =~ ^[yY][eE][sS]$ || "${response}" =~ ^[yY]$ ]]; then
            # Confirmed. Delete directory.
            echo
            echo -e " ${msg_info}  ${gray}Deleting installation directory: ${cyan}${install_dir}/${clear}"
            rm --recursive --force "${install_dir}"
        else
            # Skip deleteion.
            echo
            echo -e " ${msg_info}  ${gray}Skipping deletion.${clear}"
        fi
    else
        echo -e " ${msg_info}  ${gray}Directory ${white}'${install_dir}/' ${gray}does not exist. Skipping deletion."
    fi

    # Uninstall complete.
    echo -e "\n ${green}✓  ${white}Uninstallation complete${clear}\n\n"
}

# =============================================================================
# print_usage:
# Show usage information.
# =============================================================================
print_usage() {
    echo "Usage: install.sh [options]"
    echo "Install, upgrade, or uninstall Deceptifeed"
    echo
    echo "Options:"
    echo "  -h, --help          Display this help and exit"
    echo "  -y, --yes           Automatically confirm actions without prompting"
    echo "      --uninstall     Uninstall Deceptifeed"
    echo
    echo "Description:"
    echo "Run the script without options to install Deceptifeed or upgrade if it's"
    echo "already installed."
    echo
}

# =============================================================================
# main:
# The primary entry point of the script. This function:
#   1. Checks command-line arguments to determine whether to install (default)
#      or uninstall the application.
#   2. Calls the startup_checks function to perform initial setup and checks.
# =============================================================================
main() {
    if [[ "$#" -gt 2 ]]; then
        print_usage
        exit 0
    fi

    local uninstall_flag=false
    
    while [[ -n "$1" ]]; do
        case "$1" in
            -y | --yes)
                auto_confirm_prompts=true
                shift
                ;;
            --uninstall)
                uninstall_flag=true
                shift
                ;;
            *)
                print_usage
                exit 0
                ;;
        esac
    done

    if [ "${uninstall_flag}" == true ]; then
        startup_checks
        uninstall_app
        exit 0
    else
        startup_checks
        install_app
        exit 0
    fi
}

# Script execution starts here by calling the main function.
main "$@"