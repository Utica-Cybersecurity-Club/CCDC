#!/bin/sh

# sudo ./script.sh list              ->  list all users, groups, and permissions 
# sudo ./script.sh remove X          -> removes a user from sudoers 

case "$1" in
    list)
        echo "=== USERS ==="
        awk -F: '$3 >= 1000 && $3 < 65534 {print $1, "uid="$3}' /etc/passwd

        echo ""
        echo "=== GROUPS ==="
        cut -d: -f1 /etc/group

        echo ""
        echo "=== SUDOERS ==="
        echo "-- /etc/sudoers --"
        grep -v '^#' /etc/sudoers 2>/dev/null | grep -v '^$'
        echo ""
        echo "-- /etc/sudoers.d/ --"
        for f in /etc/sudoers.d/*; do
            [ -f "$f" ] && echo "[$f]" && grep -v '^#' "$f" | grep -v '^$'
        done 2>/dev/null
        echo ""
        echo "-- sudo group members --"
        getent group sudo wheel 2>/dev/null
        ;;

    remove)
        [ -z "$2" ] && echo "Usage: $0 remove <username>" && exit 1
        user="$2"
        if id "$user" >/dev/null 2>&1; then
            gpasswd -d "$user" sudo >/dev/null 2>&1 && echo "Removed $user from sudo group"
            gpasswd -d "$user" wheel >/dev/null 2>&1 && echo "Removed $user from wheel group"
            [ -f "/etc/sudoers.d/$user" ] && rm -f "/etc/sudoers.d/$user" && echo "Removed /etc/sudoers.d/$user"
            if grep -q "^$user" /etc/sudoers 2>/dev/null; then
                sed -i "s/^$user/#$user/" /etc/sudoers && echo "Commented out $user in /etc/sudoers"
            fi
        else
            echo "User not found: $user"
            exit 1
        fi
        ;;

    *)
        echo "Usage: $0 {list|remove <username>}"
        exit 1
        ;;
esac