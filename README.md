# csi-driver-cacerts

CSI driver that add ca certificates to a the OS trusted certificate issuers (eg, `/etc/ssl/certs/ca-certificates.crt`, `/etc/ssl/certs/java/cacerts`) so that users don't need to pass ca certificates to individual applications or use insecure mode (eg, `curl -k`).

## Why

Projects like [cert-manager](https://github.com/jetstack/cert-manager) and [cert-manage-csi-driver](https://github.com/cert-manager/csi-driver) make it very easy to deploy servers that are secured using TLS. But this requires clients of such servers to pass the ca certificate to verify server identity. This can be painful for a number of reasons:

- Say, the server is deployed in one namespace and the client application is running in a different namespace. Now, users have to copy the ca certificate via a secret into a different namespace.

- Say, the client application is talking to multiple servers each of which are using their own ca certificate issued certs. Now, users have to combine those separate ca certificates into one pem formatted file and pass that to the client application.

- Java uses its own special file format for ca certificates. Users have to have a cli called `keytool` to add these custom ca certificates and pass that to Java applications. This was one of the original motivating use-cases for this csi driver. As an example, take a look at the Graylog documentation on how to [add a self-signed certificate to the JVM trust store](https://archivedocs.graylog.org/en/2.4/pages/configuration/https.html#adding-a-self-signed-certificate-to-the-jvm-trust-store).

The UX in these types of use-cases can be simplified dramatically by using a Ephemeral CSI driver that augments the default trusted certificates of the operating system with the custom ca certificates required by a given pod. This CSI driver does exactly that.

## Example

```yaml
apiVersion: cacerts.csi.cert-manager.io/v1alpha1
kind: CAProviderClass
metadata:
  name: ca-provider
  namespace: demo
spec:
  refs:
  - apiGroup: cert-manager.io
    kind: Issuer
    # namespace:
    name: ca-issuer
---
apiVersion: v1
kind: Pod
metadata:
  name: curl-debian
  namespace: demo
spec:
  containers:
  - name: main
    image: appscode/curl:debian
    command:
    - sleep
    - "3600"
    volumeMounts:
    - name: cacerts
      mountPath: /etc/ssl/certs
  volumes:
  - name: cacerts
    csi:
      driver: cacerts.csi.cert-manager.io
      readOnly: true
      volumeAttributes:
        os: debian
        # caProviderClasses: ns1/name,ns2
        caProviderClasses: ca-provider
```

You can find more detailed examples in the examples folder.

## Installation Instructions

- First [install cert-manager](https://cert-manager.io/docs/installation/).
- Then install the cacerts CSI driver using the following helm commnads:

```
$ helm repo add appscode https://charts.appscode.com/stable/
$ helm repo update
$ helm upgrade -i cert-manager-csi-driver-cacerts appscode/cert-manager-csi-driver-cacerts -n cert-manager --wait
```

## OS Distribution Support

Different OS uses different files for trusted ca certificates. This driver has been tested against the following Linux distributions.

- alpine
- centos (8, 7)
- centos-6
- debian
- fedora
- opensuse
- oraclelinux (8, 7)
- oraclelinux-6
- rockylinux
- ubuntu

## Roadmaps and Limitations

The scope of this project is intentionally limited and there is no plan to extend it. Having said that below is a list of known issues/limitation that I intend to address:

- Support for additional OS distros. Please file an issue in this repo for this.
- Currently the contents of the mounted volume will not be updated even if the secrets / issuers are updated. Today you have to restart the pod to update the contents of the mounted volume. I intend to fix this. But there is a related issue where if the node driver pod is restarted, it forgets all the volumes mounted so far. This seems like a limitation of the Ephemeral CSI driver plugin at Kubernetes level today.
- Support for additional [External issuers](https://cert-manager.io/docs/configuration/external/).  Please contibute if you know how to write code in GO or file an issue.
