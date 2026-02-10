#!/bin/bash

#Read log file.
echo "enter user:"
read user

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Results of dbgovernor Log #
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
grep $user /var/log/dbgovernor-restrict.log | tail -n 20

echo "~~~~~~~~~~~~
# LVE Info #
~~~~~~~~~~~~"
lveinfo --period=3d --by-fault=any --display-username --user=$user

echo "~~~~~~~~~~~~~
# User Logs #
~~~~~~~~~~~~~"
ls -lhS /home/$user/access-logs/

echo "Enter which log file you wish to check:"
read log_file

echo "#######################################################"
echo "Please note, this log starts at:" `head -1 /home/$user/access-logs/$log_file | awk '{print $4}' | tr -d [`
echo "#######################################################"

# ─────────────────────────────────────────────
# Time range filter
# ─────────────────────────────────────────────
echo ""
echo "Would you like to filter results by a specific time range? (yes/no):"
read use_time_filter

if [[ "$use_time_filter" =~ ^[Yy] ]]; then
    echo "Enter start time (e.g. 09:00 or 13:00 — use 24hr format):"
    read start_time
    echo "Enter end time (e.g. 10:00 or 20:00 — use 24hr format):"
    read end_time

    # Validate basic HH:MM format
    if ! [[ "$start_time" =~ ^[0-9]{2}:[0-9]{2}$ ]] || ! [[ "$end_time" =~ ^[0-9]{2}:[0-9]{2}$ ]]; then
        echo "Invalid time format. Please use HH:MM (e.g. 09:00). Proceeding without time filter."
        use_time_filter="no"
    else
        echo ""
        echo "Filtering results between ${start_time} and ${end_time}..."
        echo ""

    fi
fi

# Helper: apply time filter to stdin if enabled, otherwise pass through
# $4 looks like [10/Feb/2026:10:31:50 — time HH:MM starts at char 13, length 5
filter_by_time() {
    if [[ "$use_time_filter" =~ ^[Yy] ]]; then
        awk -v start="$start_time" -v end="$end_time" '{
            t = substr($4, 13, 5)
            if (t >= start && t <= end) print
        }'
    else
        cat
    fi
}
# ─────────────────────────────────────────────

echo "~~~~~~~~~~~~~~~~~
# visitors today #
~~~~~~~~~~~~~~~~~"
cat /home/$user/access-logs/$log_file | grep `date '+%e/%b/%G'` | filter_by_time | awk '{print $1}' | sort | uniq -c | wc -l

echo "~~~~~~~~~~~~~~~
# top 10 ip's #
~~~~~~~~~~~~~~~"
cat /home/$user/access-logs/$log_file | filter_by_time | awk '{print $1}' | sort -n | uniq -c | sort -n | tail -n 10

echo "
~~~~~~~~~~~~~~~~~~~~~~
# Activity of top IP #
~~~~~~~~~~~~~~~~~~~~~~"
top_ip=$(cat /home/$user/access-logs/$log_file | filter_by_time | awk '{print $1}' | sort -n | uniq -c | sort -n | tail -n 1 | awk '{print $2}')
grep $top_ip /home/$user/access-logs/$log_file | filter_by_time | tail -n 5

echo "~~~~~~~~~~~~~~~~~~~~~~
# Top URLs being hit #
~~~~~~~~~~~~~~~~~~~~~~"
grep http /home/$user/access-logs/$log_file | filter_by_time | awk '{print $11}' | sort -n | uniq -c | sort -n | tail

echo "~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Top User agents #
~~~~~~~~~~~~~~~~~~~~~~~~~~~"
cat /home/$user/access-logs/$log_file | filter_by_time | awk -F\" '($2 ~ "^GET /"){print $6}' | sort -n | uniq -c | sort -n | tail

echo
echo "
~~~~ Data from log file: /home/$user/access-logs/$log_file ~~~~"
if [[ "$use_time_filter" =~ ^[Yy] ]]; then
    echo "~~~~ Time range filter applied: ${start_time} - ${end_time} ~~~~"
fi
