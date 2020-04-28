<img src="https://cfsecuritycdn.infosec.workers.dev/img/flan_scan.png"/>

Flan Scan is a lightweight network vulnerability scanner. With Flan Scan you can easily find open ports on your network, identify services and their version, and get a list of relevant CVEs affecting your network.

Flan Scan is a wrapper over Nmap and the vulners script which turns Nmap into a full-fledged network vulnerability scanner. Flan Scan makes it easy to deploy Nmap locally within a container, push results to the cloud, and deploy the scanner on Kubernetes.


Getting Started
------
1. Clone this repository

2. Make sure you have docker setup:
```bash
$ docker --version
```

3. Add the list of IP addresses or CIDRS you wish to scan to `shared/ips.txt`.

4. Build the container:
```bash
$ make build
```

5. Start scanning!
```bash
$ make start
```
By default flan creates Latex reports, to get other formats run:
```
$ make html
```
Additional supported formats are *md* (markdown), *html* and *json*.

When the scan finishes you will find the reports summarizing the scan in `shared/reports`. You can also see the raw XML output from Nmap in `shared/xml_files`.

<div>
  <img style="display: inline-block" src="https://cfsecuritycdn.infosec.workers.dev/img/flan_scan_report1.png" width="49%"/>
  <img style="display: inline-block" src="https://cfsecuritycdn.infosec.workers.dev/img/flan_scan_report2.png" width="49%"/>
</div>

Custom Nmap Configuration
-------------------------
By default Flan Scan runs the following Nmap command:

```bash
$ nmap -sV -oX /shared/xml_files -oN - -v1 $@ --script=vulners/vulners.nse <ip-address>
```
The `-oX` flag adds an XML version of the scan results to the `/shared/xml_files` directory and the `-oN -` flag outputs "normal" Nmap results to the console. The `-v1` flag increases the verbosity to 1 and the `-sV` flag runs a service detection scan (aside from Nmap's default port and SYN scans). The `--script=vulners/vulners.nse` is the script that matches the services detected with relevant CVEs.

Nmap also allows you to run UDP scans and to scan IPv6 addresses. To add these and other flags to Flan Scan's Nmap command after running `make build` run the container and pass in your Nmap flags like so:

```bash
$ docker run -v $(CURDIR)/shared:/shared flan_scan <Nmap-flags>
```

Pushing Results to the Cloud
----------------------------

Flan Scan currently supports pushing Latex reports and raw XML Nmap output files to a GCS Bucket or to an AWS S3 Bucket. Flan Scan requires 2 environment variables to push results to the cloud. The first is `upload` which takes one of two values `gcp` or `aws`. The second is `bucket` and the value is the name of the S3 or GCS Bucket to upload the results to. To set the environment variables, after running `make build` run the container setting the environment variables like so:
```bash
$ docker run --name <container-name> \
             -v $(CURDIR)/shared:/shared \
             -e upload=<gcp or aws> \
             -e bucket=<bucket-name> \
             -e format=<optional, one of: md, html or json> \
             flan_scan
```

Below are some examples for adding the necessary AWS or GCP authentication keys as environment variables in container. However, this can also be accomplished with a secret in Kubernetes that exposes the necessary environment variables or with other secrets management tools.


### Example GCS Bucket Configuration

Copy your GCS private key for a service account to the `/shared` file
```bash
$ cp <path-to-local-gcs-key>/key.json shared/
```

Run the container setting the `GOOGLE_APPLICATION_CREDENTIALS` environment variable as the path to the GCS Key

```bash
$ docker run --name <container-name> \
             -v $(CURDIR)/shared:/shared \
             -e upload=gcp \
             -e bucket=<bucket-name> \
             -e GOOGLE_APPLICATION_CREDENTIALS=/shared/key.json
             -e format=<optional, one of: md, html or json> \
             flan_scan
```

### Example AWS S3 Bucket Configuration

Set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables to the corresponding variables for your S3 service account.

```bash
docker run --name <container-name> \
           -v $(CURDIR)/shared:/shared \
           -e upload=aws \
           -e bucket=<s3-bucket-name> \
           -e AWS_ACCESS_KEY_ID=<your-aws-access-key-id> \
           -e AWS_SECRET_ACCESS_KEY=<your-aws-secret-access-key> \
           -e format=<optional, one of: md, html or json> \
           flan_scan


```

Deploying on Kubernetes
-----------------------

When deploying Flan Scan to a container orchestration system, such as Kubernetes, you must ensure that the container has access to a file called `ips.txt` at the directory `/`. In Kubernetes, this can be done with a ConfigMap which will mount a file on your local filesystem as a volume that the container can access once deployed. The `kustomization.yaml` file has an example of how to create a ConfigMap called `shared-files`. This ConfigMap is then mounted as a volume in the `deployment.yaml` file.

Here are some easy steps to deploy Flan Scan on Kubernetes:
1. To create the ConfigMap add a path to a local `ips.txt` file in `kustomization.yaml` and then run `kubectl apply -k .`.
2. Now run `kubectl get configmap` to make sure the ConfigMap was created properly.
3. Set the necessary environment variables and secrets for your cloud provider within `deployment.yaml`.
4. Now run `kubectl apply -f deployment.yaml` to launch a deployment running Flan Scan.

Flan Scan should be running on Kubernetes successfully!
