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

## CA cert location by OS Distribution

### ubuntu, debian, alpine

```
/etc/ssl/certs

/etc/ssl/certs/java/cacerts
/etc/ssl/certs/ca-certificates.crt
```

### centos-6, oraclelinux-6

```
/etc/pki

tls/cert.pem
tls/certs/ca-bundle.crt
ca-trust/extracted/pem/tls-ca-bundle.pem

java/cacerts
ca-trust/extracted/java/cacerts

ca-trust/extracted/openssl/ca-bundle.trust.crt
tls/certs/ca-bundle.trust.crt
```

### rockylinux, fedora, centos-7, centos-8, oraclelinux-7, oraclelinux-8

```
/etc/pki/ca-trust/extracted

pem/tls-ca-bundle.pem
java/cacerts
openssl/ca-bundle.trust.crt

/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
/etc/pki/ca-trust/extracted/java/cacerts
```

```
docker run -it rockylinux/rockylinux cat /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt
```

### opensuse/leap

```
sh-4.4# ls -l /var/lib/ca-certificates
total 404
-r--r--r-- 1 root root 212343 Oct 28 19:23 ca-bundle.pem
-r--r--r-- 1 root root 157576 Oct 28 19:23 java-cacerts
dr-xr-xr-x 1 root root  20480 Oct 28 19:23 openssl
dr-xr-xr-x 1 root root  20480 Oct 28 19:23 pem
```

- https://serverfault.com/questions/620003/difference-between-ca-bundle-crt-and-ca-bundle-trust-crt

All files are in the BEGIN/END TRUSTED CERTIFICATE file format,
as described in the x509(1) manual page.
