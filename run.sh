#!/bin/bash

upload="${upload:-}"
current_time="$(date "+%Y.%m.%d-%H.%M")"
if [ -z "$upload" ]
then
    root_dir=/shared/
else
    root_dir=/
    mkdir /xml_files
    mkdir /reports
fi

report_extension="${format:-tex}"

xml_dir="xml_files/$current_time"
report_file="reports/report_$current_time.$report_extension"
report_file_path="${root_dir}${report_file}"

upload() {
    if [ -z "$upload" ]
    then
        return
    fi
    if [ "$upload" = "aws" ]
    then
        python /aws_push.py "$1"
    elif [ "$upload" = "gcp" ]
    then
        python /gcp_push.py "$1"
    fi
}

get_filename() {
    echo "$1" | tr / -
}

mkdir -p "$root_dir$xml_dir"
while IFS= read -r line
do
  current_time="$(date "+%Y.%m.%d-%H.%M.%S")"
  filename="$(get_filename "$line").xml"
  # $@ without quotes required to expand additional options
  # shellcheck disable=SC2068
  nmap -sV -oX "$root_dir$xml_dir/$filename" -oN - -v1 $@ --script=vulners/vulners.nse "$line"
  upload "$xml_dir/$filename"
done < /shared/ips.txt

python /output_report.py "$root_dir$xml_dir" "$report_file_path" /shared/ips.txt
if [[ "$report_extension" = "tex" ]]
then
    sed -i 's/_/\\_/g' "$report_file_path"
    sed -i 's/\$/\\\$/g' "$report_file_path"
    sed -i 's/#/\\#/g' "$report_file_path"
    sed -i 's/%/\\%/g' "$report_file_path"
fi
upload "$report_file_path"
