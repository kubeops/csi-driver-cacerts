# cert-manager CSI Driver

```
$ kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.5.4/cert-manager.yaml
$ helm upgrade -i -n cert-manager cert-manager-csi-driver jetstack/cert-manager-csi-driver --wait

$ kubectl create ns demo
$ cd samples/ca-issuer
$ openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout ./ca.key -out ./ca.crt -subj "/CN=mongo/O=kubedb"
$ kubectl create secret tls ca \
       --cert=ca.crt \
       --key=ca.key \
       --namespace=demo
$ kubectl create -f issuer.yaml
$ kubectl apply -f nginx.yaml
```

https://172.18.0.2:30789/

```
$ cd ~/go/src/kubeops.dev/csi-driver-cacerts
$ kubectl apply -f crds/cacerts.csi.cert-manager.io_caproviderclasses.yaml

kubectl apply -f curl-alpine.yaml
kubectl apply -f curl-centos6.yaml
kubectl apply -f curl-centos7.yaml
kubectl apply -f curl-centos8.yaml
kubectl apply -f curl-debian.yaml
kubectl apply -f curl-fedora.yaml
kubectl apply -f curl-opensuse.yaml
kubectl apply -f curl-rockylinux.yaml
kubectl apply -f curl-ubuntu.yaml

$ watch kubectl get pods -n demo
NAME                     READY   STATUS    RESTARTS   AGE
curl-alpine              1/1     Running   0          4m34s
curl-centos6             1/1     Running   0          4m18s
curl-centos7             1/1     Running   0          3m38s
curl-centos8             1/1     Running   0          3m38s
curl-debian              1/1     Running   0          3m37s
curl-fedora              1/1     Running   0          3m37s
curl-opensuse            1/1     Running   0          3m37s
curl-rockylinux          1/1     Running   0          3m36s
curl-ubuntu              1/1     Running   0          3m36s
nginx-594bc689d7-74gtr   1/1     Running   0          23h

$ kubectl exec -it curl -- bash
root@curl:/# curl https://nginx.demo.svc.cluster.local
```

# Testing cert-manager

- Start off by generating you ca certificates using openssl.

```bash
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout ./ca.key -out ./ca.crt -subj "/CN=mongo/O=kubedb"
```

```bash
kubectl create ns demo
```

- Now create a ca-secret using the certificate files you have just generated.

```bash
kubectl create secret tls ca \
     --cert=ca.crt \
     --key=ca.key \
     --namespace=demo
```

Now, create an `Issuer` using the `ca-secret` you have just created. The `YAML` file looks like this:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: ca-issuer
  namespace: demo
spec:
  ca:
    secretName: ca
```

```bash
kubectl create -f issuer.yaml

kubectl create -f cert.yaml
```

```bash
$ kubectl get secrets -n demo
NAME                  TYPE                                  DATA   AGE
default-token-tgjlz   kubernetes.io/service-account-token   3      10m
ca                    kubernetes.io/tls                     2      10m
mycert-tls            kubernetes.io/tls                     3      5m33s

$ kubectl view-secret -n demo mycert-tls
Multiple sub keys found. Specify another argument, one of:
-> ca.crt
-> tls.crt
-> tls.key

$ kubectl view-secret -n demo mycert-tls ca.crt
-----BEGIN CERTIFICATE-----
MIIDIzCCAgugAwIBAgIUfusT4Oj1uXMuUJ05AZG1gDz5px0wDQYJKoZIhvcNAQEL
BQAwITEOMAwGA1UEAwwFbW9uZ28xDzANBgNVBAoMBmt1YmVkYjAeFw0yMDA4MDcw
NDMyMzRaFw0yMTA4MDcwNDMyMzRaMCExDjAMBgNVBAMMBW1vbmdvMQ8wDQYDVQQK
DAZrdWJlZGIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDwVVSXBRME
rfXVu23cMqRoPr3JFGlIGxqgPzN+wlteOlTQptVkbt+qv44Lrk1n45AFvNe+dEpI
XLvt6B9dkJhDz34Cj4MwWeOekSJ2jmWxMSNArD4MoCCIyIq++4xYGBsf9Xx2Frtd
fvg9qp4QcLEmzqWh/w3TikNY2QZWe726BlatdugP7xxrJXG8E5Hi6xK9ukbsG+xd
DE0snXr++dp+qBaumo0hjGuS6QlErqAnm4LwPXxiZSRmGVGgtj0NmZD+jkI48UI8
Lfl9GCfbczcD3+ludlpNksnEQGpxABfhtYcw5357p+KJw5fVQjRdRzT5pZ/vtU3g
B+g83sWEBSVjAgMBAAGjUzBRMB0GA1UdDgQWBBSQjI2uKX0jicKnVo0EbQd8EFYI
NjAfBgNVHSMEGDAWgBSQjI2uKX0jicKnVo0EbQd8EFYINjAPBgNVHRMBAf8EBTAD
AQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCCoY503sixXQ7246jLvU246wcc64ulTQGb
4oAdDOjK9b55sY/ZU+aBZXNwK50UNU1Nkp6z6KjBZcTWUDwwOad2/RSSSCitL+Tv
NBr+fH0y/qoQvLUxEJq/rMd/6s5r4bjcRO6m+hekr/L7KSISyrGspUVDHxdHlWOm
RR2azvXWAqNYGorm9fpeRjnCrIvMTRiR7yw0l/3HHRYsysOTkLd7CdIwIS75dk6P
TISRT+2N9H0O9wJZtbpgXwy3mLR/yXhd0y6XHI9f4NXTxnG6K480eaJf5ng8wktQ
HTUsNM2cNy69KwgxR0KA4H6mFEoPWlk8ojFTSxCIieWzsv95Pdm6
-----END CERTIFICATE-----

$ kubectl view-secret -n demo mycert-tls tls.crt
-----BEGIN CERTIFICATE-----
MIIDIDCCAgigAwIBAgIRAMokuhF5tBxEa7nVEE31BvYwDQYJKoZIhvcNAQELBQAw
ITEOMAwGA1UEAwwFbW9uZ28xDzANBgNVBAoMBmt1YmVkYjAeFw0yMDA4MDcwNDM3
MjFaFw0yMDExMDUwNDM3MjFaMAAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQCbRHPysERf3yzqAv+nkPOFnQPmCRSXYl99yKMwQtjKaByNN2y75PvvS8x0
2ezif+xMTRR1gpZUSKDNGxTeNdJnyhHhUD1hFbd4FctIpmxrDl8uewTK+ailr6d4
JcsZL/gMr4M6hZbcmuTf8Ypfi+6EITbwK4fKQd+tWZHgsVci0jChs2gSNqsQyuKg
1snlpop12o4mNsYVsJ2cbD7UWwp5lzLwM13wg5e31J1DUei2E2I73Yc1eFwy6/wf
vFZJv4NGR/bURBOsIBY+DoF7jQ+IcTW16U1LNtCiOndlhL45qluP7udrRndhwsb9
c8T20eWeoUNXHgQEPvSUsGb5nFF/AgMBAAGjdDByMA4GA1UdDwEB/wQEAwIFoDAM
BgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFJCMja4pfSOJwqdWjQRtB3wQVgg2MDEG
A1UdEQEB/wQnMCWCDSouZXhhbXBsZS5jb22CC2V4YW1wbGUuY29tggdmb28uY29t
MA0GCSqGSIb3DQEBCwUAA4IBAQCTcs6cN2oEPF5LKIsbzuVFrPexs7kg9kCzZ/wJ
cUsPUI2wVO4oEIuM7S0L3fCOTgouBM67jOpGG1kFYI7wLipAxKwpgamdcZ+M90yT
LYlmK7ZyjyYMeFBCL73+uYkaSGQmQkLGAfCA+RVbfUZ1lh0rgE+xRohedw0JaF67
LhB92qZW3WbHVPctMt/h7A5ZdF/5qdZ/R6uBTLG4jNX3/hSLD4d53R6xdTs4UDQS
PLhBM1W8TC5XEbeKzCm3tTeVRW/AIVL8Q6lHiAnlbidS7ETesODRcxK1yshyI31N
3Vt5Zzf4amAPNIip59OnjCi7v9DageWG+cX7C+jUGcVDDUzf
-----END CERTIFICATE-----

$ kubectl view-secret -n demo mycert-tls tls.key
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAm0Rz8rBEX98s6gL/p5DzhZ0D5gkUl2JffcijMELYymgcjTds
u+T770vMdNns4n/sTE0UdYKWVEigzRsU3jXSZ8oR4VA9YRW3eBXLSKZsaw5fLnsE
yvmopa+neCXLGS/4DK+DOoWW3Jrk3/GKX4vuhCE28CuHykHfrVmR4LFXItIwobNo
EjarEMrioNbJ5aaKddqOJjbGFbCdnGw+1FsKeZcy8DNd8IOXt9SdQ1HothNiO92H
NXhcMuv8H7xWSb+DRkf21EQTrCAWPg6Be40PiHE1telNSzbQojp3ZYS+Oapbj+7n
a0Z3YcLG/XPE9tHlnqFDVx4EBD70lLBm+ZxRfwIDAQABAoIBAGR5OnK8X7KOb7kK
sbcUVJGM1p4AGEQSE2sI75jmWPU5w+gaCpHYDrN+IFMpRmIXl6iUZH3aQD9QNEYl
lS5qM7qYB1P/IYj2jZ/2snJTx2rLhQpF7wcN4XU+IqfcBP5KjUBgPxIaqlIdJahI
3FsR6Qm1mKB3+soGMKEzifOVrqZHzcrqx/7+RsDFFy262Ycb0noFAslVAIrzmh9Q
QYXzb1VvpYwJ+4Kydz/9tXQGKrbGM0sNaQhDKQGUEu5lEEWpQpxO1NChZ1f6qlkN
V1lrDhYkXNyUwy5qwwrGcReTaaY3Bd2dG3QEnCV1npFZV+rK3adG3TBnmAYVjQpf
/bRYVckCgYEAx+TfnR5Ajf0tMT06kei0rHY2VPZ5qXd7JyGRCRxQjOiloi0LsqUl
iwWd4oQFu3/58eqWES1amJptJddgvODXZxff/vhFjsh18aY8lGHjMmH1jLG92u2S
pBcvA8ZNjHEdzFvRaDBJFbO0xVtVuitCnXiX0k0KbSPYvq3MfztYZFMCgYEAxtj9
bT6SACGtA4WuB92emMePVRdHwHWw992j/UVRg4G//oTfqCzs+Zy2UcAzBKu9AhWT
CXZGPKJbyUufodH640pQ5vRZmOdlJPBXKQ5GvgNarVCIe2UuYcNpBHqHbf5E+ock
CkRvuqglfO8f+/sap6Nt1L3qd2kUSHVbPtdYuKUCgYEAxAkhg+T3SkjQ2UlC93VQ
OxJzlj9icWBL1sSEiHrMRGSki7fBkSGFACIyBMOVG50WcrmtEot4HdDU2hevN40J
soEnm9W/4ZeWk7aEEsEtH2wSdDicCOiUt3hFE16XDvSgVJp3c8Zm5nGnByXbnQhv
/B8YRZZoc0CEf/vSYbTBqyECgYEAtI7SSAFZ536ssJcROJk3arlCYFycTZlQkTGT
t+Xap5QIt18GC5qHr/xp3P+uE96x6JOYiS35hxNSTw05LWIS85JGtgBI3zu2Lv2B
14jcGavICbonxAxTOniLAoMUOH97ORW/VwdfgNkv+SrVGySexnvyvguZPMaQoV7W
9M/sAvUCgYEAgwOs6LbzOwvH3fV4glIYkeppiQdKVA67uBYXm7Aelehx/7eS4OFO
8/KcE6EWFDi9pJmhPWeNWn1FEepEAveZ2+cjklRU93ge2Aa4vbXeqXifxGiGteAF
xT/LBlHkzIlNKjLphp/6SPmceDb5cRTZKOCC8wX+R28F07SuVIOgcBk=
-----END RSA PRIVATE KEY-----
```

## ubuntu, debian, alpine

/etc/ssl/certs

/etc/ssl/certs/java/cacerts
/etc/ssl/certs/ca-certificates.crt

## centos-6, oraclelinux-6

/etc/pki

tls/cert.pem
tls/certs/ca-bundle.crt
ca-trust/extracted/pem/tls-ca-bundle.pem

java/cacerts
ca-trust/extracted/java/cacerts

ca-trust/extracted/openssl/ca-bundle.trust.crt
tls/certs/ca-bundle.trust.crt



## rockylinux, fedora, centos-7, centos-8, oraclelinux-7, oraclelinux-8

/etc/pki/ca-trust/extracted

pem/tls-ca-bundle.pem
java/cacerts
openssl/ca-bundle.trust.crt

/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
/etc/pki/ca-trust/extracted/java/cacerts

```
$ docker run -it rockylinux/rockylinux cat /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
```

## opensuse/leap

```
sh-4.4# ls -l /var/lib/ca-certificates
total 404
-r--r--r-- 1 root root 212343 Oct 28 19:23 ca-bundle.pem
-r--r--r-- 1 root root 157576 Oct 28 19:23 java-cacerts
dr-xr-xr-x 1 root root  20480 Oct 28 19:23 openssl
dr-xr-xr-x 1 root root  20480 Oct 28 19:23 pem
```




# https://serverfault.com/questions/620003/difference-between-ca-bundle-crt-and-ca-bundle-trust-crt

All files are in the BEGIN/END TRUSTED CERTIFICATE file format,
as described in the x509(1) manual page.

