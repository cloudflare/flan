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

xml_dir=xml_files/$current_time
report_file=reports/report_$current_time.tex

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
    echo $1 | tr / -
}

function export_report {
  if [[ -z $export ]]
  then
    return
  elif [ $export = "latex" ]
  then
    python export_latex.py $1 $2 $3
    sed -i 's/_/\\_/g' $2
    sed -i 's/\$/\\\$/g' $2
    sed -i 's/#/\\#/g' $2
    sed -i 's/%/\\%/g' $2
  elif [ $export = "neo4j" ]
  then
    python export_neo4j.py $root_dir$xml_dir
  fi
}

mkdir $root_dir$xml_dir
while IFS= read -r line
do
  current_time=$(date "+%Y.%m.%d-%H.%M.%S")
  filename=$(get_filename $line)".xml"
  nmap -sV -oX $root_dir$xml_dir/$filename -oN - -v1 $@ --script=vulners/vulners.nse $line
  upload $xml_dir/$filename
done < /shared/ips.txt

python /parse_report.py $root_dir$xml_dir
export_report $root_dir$xml_dir $root_dir$report_file /shared/ips.txt
upload $report_file
