#!/bin/sh

current_time=$(date "+%Y.%m.%d-%H.%M")
if [[ -z $upload ]]
then
    root_dir=/shared/
else
    root_dir=/
    mkdir /xml_files
    mkdir /reports
fi

report_extension="tex"

if [[ ! -z $format ]]
then
    report_extension=$format
fi

xml_dir=xml_files/$current_time
report_file=reports/report_$current_time.$report_extension

function upload {
    if [[ -z $upload ]]
    then
        return
    elif [ $upload = "aws" ]
    then
        python /aws_push.py $1
    elif [ $upload = "gcp" ]
    then
        python /gcp_push.py $1
    fi
}

function get_filename(){
    echo "$1" | tr -d '"' | tr ' /' '_-'
}

mkdir $root_dir$xml_dir
while IFS= read -r line
do
  current_time=$(date "+%Y.%m.%d-%H.%M.%S")
  filename=$(get_filename $line)".xml"
  nmap -sV -oX $root_dir$xml_dir/$filename -oN - -v1 $@ --script=vulners/vulners.nse $line
  upload $xml_dir/$filename
done < /shared/ips.txt

python /output_report.py $root_dir$xml_dir $root_dir$report_file /shared/ips.txt
if [[ $report_extension = "tex" ]]
then
    sed -i 's/_/\\_/g' $root_dir$report_file
    sed -i 's/\$/\\\$/g' $root_dir$report_file
    sed -i 's/#/\\#/g' $root_dir$report_file
    sed -i 's/%/\\%/g' $root_dir$report_file
fi
upload $report_file
