# Docker Registry Setup with Secure Connection, Authentication and Authorization

# Docker Installation and Setup

To install docker with the required dependencies needed just create a bash file to run this script

```bash
#!/bin/bash

sudo apt-get update
sudo apt-get install \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

sudo mkdir -m 0755 -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update

sudo chmod a+r /etc/apt/keyrings/docker.gpg
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

sudo docker run hello-world

sudo dpkg -i ./containerd.io_<version>_<arch>.deb \
  ./docker-ce_<version>_<arch>.deb \
  ./docker-ce-cli_<version>_<arch>.deb \
  ./docker-buildx-plugin_<version>_<arch>.deb \
  ./docker-compose-plugin_<version>_<arch>.deb

sudo service docker start
sudo docker run hello-world
```

# Setting up the environment for the .pfx SSL Certificate

### Prerequisites

- **A .pfx file**
- **Openssl-1.1.1q version**

First, you need to have the wild card certificate with a **.pfx** extension that includes the official certificate and its key protected by a passphrase.

To extract the certificate and the key, it is needed to use **OpenSSL** to do that job.

The preinstalled OpenSSL by default in Ubuntu 22.04 is **3.0.2-0ubuntu1.6**

![Untitled.png](Docker%20Registry%20Setup%20with%20Secure%20Connection,%20Auth%20b4edfd26de4445c1b14bb45fdbdeaea1/Untitled.png)

After some attempts to extract the certificate and key from the .pfx file using the OpenSSL command

```bash
openssl pkcs12 -in yourfile.pfx -nocerts -out encrypted_ssl_certificate_secret.key
```

we get that error message

```bash
Error outputting keys and certificates
40C749D1A87F0000:error:0308010C:digital envelope routines:inner_evp_generic_fetch:unsupported:../crypto/evp/evp_fetch.c:349:Global default library context, Algorithm (RC2-40-CBC : 0), Properties ()
```

**Googling around seems like this certificate uses some sort of legacy encryption technology no longer supported by Open SSL version 3.0.2-0ubuntu1.6**

In conclusion, some research found that OpenSSL's old versioning scheme (1.1.1)

`openssl-1.1.1q` is the one that works with that type of certificate (.pfx file)

## Setting up openssl-1.1.1q version

### 1- Remove the existing OpenSSL

`sudo apt purge openssl -y`

### 2- Installation prerequisites

As the manual process required building OpenSSL, you'd have to install the prerequisites:

```bash
sudo apt install build-essential checkinstall zlib1g-dev -y
```

Once you're done with installing prerequisites, change your directory to `/usr/local/src/`:

```bash
cd /usr/local/src/
```

### 3- Download and install OpenSSL v1.1.1q

Now, use the wget command to download OpenSSL:

```bash
sudo wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1q.tar.gz
```

Once you are done with downloading, extract the tar file using the tar utility:

```bash
sudo tar -xf openssl-1.1.1q.tar.gz
```

And navigate to the recently extracted tar file:

```bash
cd openssl-1.1.1q
```

Now, let's start the installation process by configuration process and it should give you make file:

```bash
sudo ./config --prefix=/usr/local/ssl --openssldir=/usr/local/ssl shared zlib
```

![https://learnubuntu.com/content/images/2022/11/creates-make-file-for-us.png](https://learnubuntu.com/content/images/2022/11/creates-make-file-for-us.png)

Now, let's invoke the make command to build OpenSSL:

```bash
sudo make
```

To check whether there are no errors in the recent build, use the given command:

```bash
sudo make test
```

![https://learnubuntu.com/content/images/2022/11/all-test-were-successfull.png](https://learnubuntu.com/content/images/2022/11/all-test-were-successfull.png)

And if everything goes right, you will get the message **"All tests successful"**. So now, you can proceed with the installation:

```bash
sudo make install
```

### 4- Configure OpenSSL shared libraries

First, let's create `openssl-1.1.1q.conf` for OpenSSL shared libraries at `/etc/ld.so.conf.d/` using the given command:

```bash
sudo nano /etc/ld.so.conf.d/openssl-1.1.1q.conf
```

And add the following line to that config file:

```bash
/usr/local/ssl/lib
```

![https://learnubuntu.com/content/images/2022/11/add-following-line-in-config-file.png](https://learnubuntu.com/content/images/2022/11/add-following-line-in-config-file.png)

FSave the config file and reload it to apply recently made changes using the given command:

```
sudo ldconfig -v
```

### 5- Configure OpenSSL Binary

Now, open the environment PATH variable using the given command:

```bash
sudo nano /etc/environment
```

And add`:/usr/local/ssl/bin` to the end to add `/usr/local/bin/openssl` folder to the PATH variable:

```bash
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/usr/local/ssl/bin"
```

![https://learnubuntu.com/content/images/2022/11/add-environment-variable-1.gif](https://learnubuntu.com/content/images/2022/11/add-environment-variable-1.gif)

Save and exit the editor and now reload the PATH variable using the given command:

```bash
source /etc/environment
```

Now, you can check for the installed OpenSSH version:

```bash
openssl version -a
```

Should be OpenSSl v 1.1.1q

**Now the environment should be set for our certificate extraction**

# Extracting the Certificate and Key from the .pfx file

First, it is needed to change the directory to the location of the .pfx certificate

## 1- **Extract an encrypted version of the certificate key**

Run the following command to get an encrypted version of the private key.

```bash
openssl pkcs12 -in <your_file>.pfx -nocerts -out encrypted_server.key
```

You will be asked to enter the password used to create the .pfx file you’ve got, that’s the first step. Then you’ll be prompted to input a second password: this last password is meant for protecting the real key that is contained in the .pfx file.

## 2- **Extract the actual the certificate key**

We need to extract the real private key so run the following

```bash
openssl rsa -in encrypted_server.key -out server.key
```

Type in the second password that you set to protect the private key file in the previous step.

You should see the ***server.key*** in the current directory.

## 3- **Extract the certificate**

We’re done with extracting the private key. We need to do the same for the certificate.

```bash
openssl pkcs12 -in <your_file.pfx> -clcerts -nokeys -out server.crt
```

We have extracted the SSL certificate.

## 4- Bundle up the intermediate certificate with the primary certificate

First, we need to create a directory for our certificates

Now we need to concatenate the primary certificate **(server.crt)** with the intermediate certificate **(insert the intermediate certificate instead of <intermediate_certificate.crt>)**

```bash
sudo mkdir -p /home/test1/docker_dir/certs
```

Then concatenate the certificates and move the output and the extracted key to the created certs directory

```bash
sudo cat server.crt <intermediate_certificate.crt> > ../docker_dir/certs/server.crt
sudo cp server.key /home/test1/docker_dir/certs
```

**Now our bundled certificate and its key are available and can be used to secure our upcoming connections.**

# Set the environment for building the registry

## 1. Local registry

To create a local registry, a volume should exist first to store the registry contents (images).

So let's create the path to our volume on our local machine

**Our working directory is**

```bash
cd /home/test1
```

**Recommend running the following commands with root (sudo) privilege**

```bash
mkdir -p /home/test1/docker_dir/docker_registry
```

## 2. Authentication and Authorization

Configure and set up authentication for valid users to the registry and web UI

### Set up the environment for the Proxy Authentication and Authorization

1. **Storing credentials for users and creating groups**
    
    In order to store user credentials (authentication) to have access to the local docker registry, we need to create a directory to store the credentials.
    
    Here we use **htpasswd**
    
    ### **What is htpasswd?**
    
    It is an Apache utility that allows you to protect a part of your application or the whole application with username and password at the server level. `htpasswd` is used to create and update the flat files used to store usernames and passwords for basic authentication of HTTP users. `htpasswd` encrypts passwords using either bcrypt, a version of MD5 modified for Apache, SHA1, or the system’s `crypt()`  routine. Files managed by `htpasswd` may contain a mixture of different encoding types of passwords; some user records may have bcrypt or MD5-encrypted passwords while others in the same file may have passwords encrypted with `crypt()`. Passwords will be stored in an encrypted format and the username will be in plaintext.
    
    ### **How to setup and use htpasswd**
    
    1. **Install apache2 package**
        
        ```bash
        apt install apache2-utils
        ```
        
    2. **Create htpasswd file**
        
        To create htpasswd file inside the docker we have to create a directory for the authentication inside our created volume, these credentials will be used to authenticate to our local docker registry.
        
        ```bash
        mkdir -p /home/test1/docker_dir/auth
        docker run --entrypoint htpasswd httpd:2.4 -Bbn test password > /home/test1/docker_dir/auth/httpd.htpasswd
        ```
        
    
    To validate the previous steps and check the username and pass authentication you may run the:
    
    ```bash
    htpasswd -vb /home/test1/docker_dir/auth/httpd.htpasswd test password
    ```
    
    We will create another user and add this user to the push group so lets append the currently created user to the previously created httpd.htpasswd file by
    
    ```bash
    docker run --entrypoint htpasswd httpd:2.4 -Bbn testpush password >> /home/test1/docker_dir/auth/httpd.htpasswd
    ```
    
    1. **Create httpasswd group**
        
        For the pushers to be permitted to perform push action we will create a group to have the authorized users do the push action and add a valid user to that group.
        
        ```bash
        echo "pusher: testpush" > /home/test1/docker_dir/auth/httpd.groups
        ```
        
        Now we have a valid user that has read-only access **(test)** enabling him to **view and pull** containers from the private local registry only and another one with write access (**testpush**) to be able to perform **push action** and we will define that while configuring the proxy server.
        
2. **Proxy Server Configuration**
    
    We need to create an Apache configuration file to set up the server.
    
    First copy the bundled certificate and key to auth directory
    
    ```bash
    sudo cp /home/test1/docker_dir/cert/server.crt /home/test1/docker_dir/auth/domain.crt
    sudo cp /hometest1/docker_dir/cert/server.key /home/test1/docker_dir/auth/domain.key
    ```
    
    Then create the **httpd.conf** file for the Apache server
    
    ```bash
    sudo nano -p /home/test1/docker_dir/auth/httpd.conf
    ```
    
    Then insert the following script
    
    ```bash
    LoadModule mpm_event_module modules/mod_mpm_event.so
    #LoadModule mpm_prefork_module modules/mod_mpm_prefork.so
    #LoadModule mpm_worker_module modules/mod_mpm_worker.so
    LoadModule headers_module modules/mod_headers.so
    
    LoadModule authn_file_module modules/mod_authn_file.so
    LoadModule authn_core_module modules/mod_authn_core.so
    LoadModule authz_groupfile_module modules/mod_authz_groupfile.so
    LoadModule authz_user_module modules/mod_authz_user.so
    LoadModule authz_core_module modules/mod_authz_core.so
    LoadModule auth_basic_module modules/mod_auth_basic.so
    LoadModule access_compat_module modules/mod_access_compat.so
    
    LoadModule log_config_module modules/mod_log_config.so
    
    LoadModule ssl_module modules/mod_ssl.so
    
    LoadModule proxy_module modules/mod_proxy.so
    LoadModule proxy_http_module modules/mod_proxy_http.so
    
    LoadModule unixd_module modules/mod_unixd.so
    
    <IfModule ssl_module>
        SSLRandomSeed startup builtin
        SSLRandomSeed connect builtin
    </IfModule>
    
    <IfModule unixd_module>
        User daemon
        Group daemon
    </IfModule>
    
    ServerAdmin user@example.com    ## optional server admin mail
    
    ErrorLog /proc/self/fd/2
    
    LogLevel warn
    
    <IfModule log_config_module>
        LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
        LogFormat "%h %l %u %t \"%r\" %>s %b" common
    
        <IfModule logio_module>
          LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
        </IfModule>
    
        CustomLog /proc/self/fd/1 common
    </IfModule>
    
    ServerRoot "/usr/local/apache2"
    
    Listen 5043
    
    <Directory />
        AllowOverride none
        Require all denied
    </Directory>
    
    <VirtualHost *:5043>  ## Listen on port 5043
    
      ServerName <Domain-Name>    ## Insert the server Domain Name
    
      SSLEngine on
      SSLCertificateFile /usr/local/apache2/conf/domain.crt  ## The bundled certicicate
      SSLCertificateKeyFile /usr/local/apache2/conf/domain.key  ## The extracted key
    
      SSLCompression off
    
      # POODLE and other stuff
      SSLProtocol all -SSLv2 -SSLv3 -TLSv1
    
      # Secure cypher suites
      SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
      SSLHonorCipherOrder on
    
      Header always set "Docker-Distribution-Api-Version" "registry/2.0"
      Header onsuccess set "Docker-Distribution-Api-Version" "registry/2.0"
      RequestHeader set X-Forwarded-Proto "https"
    
      ProxyRequests     off
      ProxyPreserveHost on
    
      # no proxy for /error/ (Apache HTTPd errors messages)
      ProxyPass /error/ !
    
      ProxyPass        /v2 http://registry:5000/v2
      ProxyPassReverse /v2 http://registry:5000/v2
    
      <Location /v2>   ## Location for authentication and authorization
        Order deny,allow
        Allow from all
        AuthName "Registry Authentication"
        AuthType basic
        AuthUserFile "/usr/local/apache2/conf/httpd.htpasswd"  ## the user credentials file
        AuthGroupFile "/usr/local/apache2/conf/httpd.groups"   ## the group file for pushers
    
        # Read access to authentified users (Pull actions only)
        <Limit GET HEAD>
          Require valid-user
        </Limit>
    
        # Write access to Deployers only (Authorize Push action)
        <Limit POST PUT DELETE PATCH>
          Require group pusher
        </Limit>
    
      </Location>
    
    </VirtualHost>
    ```
    

## 3. WEB UI

Create the site’s configuration file for the UI defining the port as this site configuration will be copied to the container into **/etc/apache2/sites-available** to be enabled and run its configurations after the Apache container is created and run.

So let’s create the conf file, name it **your-domain-name.conf**

```bash
sudo nano /home/test1/installers/your-domain-name.conf
```

then insert the following script

```
<VirtualHost *:443>     ## listen on port 443

    DocumentRoot /var/www/html       ## The Main web app location
    ServerName Domain-Name           ## Domain-Name

    <Directory /var/www/html>
      Options -Indexes
      RewriteEngine on

      # Don't rewrite files or directories
      RewriteCond %{REQUEST_FILENAME} -f [OR]
      RewriteCond %{REQUEST_FILENAME} -d
      RewriteRule ^ - [L]

      # Rewrite everything else to index.html to allow html5 state links
      RewriteRule ^ index.html [L]
    </Directory>

    # When FRONTEND_BROWSE_ONLY_MODE is defined in envvars
    # We will only allow GET requests to the frontend. All other
    # HTTP requests will be aborted with an HTTP 403 Error.

    <IfDefine FRONTEND_BROWSE_ONLY_MODE>
      <Location />
        <LimitExcept GET>
          Order Allow,Deny
          Deny From All
        </LimitExcept>
      </Location>
    </IfDefine>

    # Proxy all docker REST API registry
    # requests to the docker registry server.

    <IfModule ssl_module>
       SSLProxyEngine on
       # SSLProxyVerify none
       SSLProxyCheckPeerCN off
       SSLProxyCheckPeerName off
    </IfModule>

    ProxyPreserveHost Off
    ProxyPass /v2/ ${DOCKER_REGISTRY_SCHEME}://${DOCKER_REGISTRY_HOST}:${DOCKER_REGISTRY_PORT}/v2/
    ProxyPassReverse /v2/ ${DOCKER_REGISTRY_SCHEME}://${DOCKER_REGISTRY_HOST}:${DOCKER_REGISTRY_PORT}/v2/

    # Enable SSL encryption

    SSLEngine on
        # Needs to copy the bundled cert and the key to this the specified location
    SSLCertificateFile /etc/apache2/ssl/cert/server.crt
    SSLCertificateKeyFile /etc/apache2/ssl/key/server.key

    <Location /v2/_ping>
      Satisfy any
      Allow from all
    </Location>

</VirtualHost>
```

# Creating the docker-compose file

The docker-compose file will create 3 containers:

1. Proxy server (Apache Authenticator)
    - The Proxy server will be responsible for authenticating valid users to log in through the registry and the web UI and also to authorize read and write users (pull or push).
2. Private Registry (Registry:v2)
    - The private registry will store all the containers pushed and committed in the specified volumes in the machine.
3. Web UI (Apache)
    - The web UI will be the interface where the contents of the registry (containers) are listed for users to navigate through and pull images easily.

All 3 containers will be using the bundled SSL certificate to create a secure connection.

Let’s create the docker-compose.yml file

```bash
mkdir -p /home/test1/installers/
sudo nano /home/test1/installers/docker-compose.yml
```

then write the following

```yaml
version: '3'
services:
    ## The Proxy server (Apache Authenticator)
        apache:
        container_name: Apache-Auth
        image: httpd:2.4
        hostname: Domain-Name          ## Insert the Registry Domain Name
        ports:
            - 5043:5043                ## Proxy to listen on port 5043 as in httpd.conf
        links:
            - registry:registry        ## handles the communication over network between the registry and the proxy.
        volumes:
               ## Map the /conf inside the container to the auth directory
            - /home/test1/docker_dir/auth:/usr/local/apache2/conf
        restart: always

        ## The Private Registry (Registry:v2)
    registry:
        container_name: docker-registry
        image: registry:2
        ports:
            - 127.0.0.1:5000:5000       ## Runs on the Localhost on port 5000
        restart: always
        volumes:
               ## Maps the registry of the container to the volume on the server
            - /home/test1/docker_dir/docker_registry:/var/lib/registry
               ## Maps the /cert of the container to the certs directory inside the volume on the server
            - /home/test1/docker_dir/certs:/certs

        ## Web UI (Apache)
    docker-registry-ui:
        container_name: docker-registry-ui
        image: konradkleine/docker-registry-frontend:v2
        ports:
            - 443:443
        restart: always
        environment:
            ENV_DOCKER_REGISTRY_HOST: docker.example.net  ## Domain-Name
            ENV_DOCKER_REGISTRY_PORT: 5043                ## Listen on port 5043
            ENV_DOCKER_REGISTRY_USE_SSL: 1                ## Boolean to allow SSL
```

**Now that all is set and the registry, apache and web UI should be secured with the wild card certificate and ready to run.**

## Run the docker-compose file

**To have permission to connect to the docker daemon and have access to containers we need to execute the following command**

```bash
sudo chmod 666 /var/lib/docker.sock
```

Now we can run the containers using the compose file in detached mode using

```bash
cd /home/test1/installers
```

```bash
docker compose up -d
```

And check the status of these containers using

```bash
docker ps
```

After containers have started and run successfully we need to copy the web UI site conf file to the target path as mentioned before to view the interface securely as needed and list the registry images.

As we created the **your-domain-name.conf** file on the server side we need to copy it inside the docker-registry-ui running container. Also, we need to copy the bundled certificate and the key to the location where the conf file will target the certificate to use SSL.

So let's go with the following

```bash
sudo docker cp /home/test1/installers/your-domain-name.conf docker-registry-ui:/etc/apache2/sites-available/your-domain-name.conf
sudo docker cp /home/test1/docker_dir/certs/server.crt docker-registry-ui:/etc/apache2/server.crt
sudo docker cp /home/test1/docker_dir/certs/server.key docker-registry-ui:/etc/apache2/server.key
```

Then we need to access the container to enable the site and copy the SSL Cert and the key to the target location and enable the your-domain-name.conf site file to do that:

```bash
sudo docker exec -it <container-id> bash
```

```bash
mkdir -p /etc/apache2/ssl/key/
mkdir -p /etc/apache2/ssl/cert/
mv /etc/apache2/server.key /etc/apache2/ssl/key/server.key
mv /etc/apache2/server.cert /etc/apache2/ssl/cert/server.cert
```

Now we need to enable the **your-domain-name.conf** site

```bash
cd /etc/apache2/sites-available/
ls
```

You should see **your-domain-name.conf**

Enable the site to add a symlink to sites-enabled

```bash
a2ensite docker.example.net.conf
```

Then check for the status of the conf file

```bash
apache2ctl configtest
```

```
Output:
AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 172.18.0.2. Set the 'ServerName' directive globally to suppress this message
Syntax OK
```

Finally, reload the Apache service

```bash
service apache2 reload
```

# Test the Secure connection for our registry on port 5043

To test the updated certificate run this command **(insert docker’s username and password instead of <user>, <password> and <Domain_Name>)**

```bash
curl -kiv -H "Authorization: Basic $(echo -n "<user>:<password>" | base64)" https://<Domain_Name>:5043/v2/_catalog
```

Also, you may try to browse **https://<Domain_Name>:5043/v2/_catalog** and check the secure connection and the certificate from the Key icon on your browser

**Now we can pull and push images and containers securely from our private registry.**

# Testing Pulling and Pushing on the private registry

Now we will test the previous setup to push and pull images from our local repository

### 1- **Using Test user (pull only)**

1. Log in to the local docker registry **(type in the registry)** and enter the username and password
    
    ```bash
    docker login <registry-ip>:5043
    ```
    
2. Pull the hello-world image from the docker hub to be pushed to our local registry
    
    ```bash
    docker pull hello-world
    ```
    
3. Tag the downloaded container image with a proper name inside our local registry defining the name of the local registry and the port number
    
    ```bash
    docker tag hello-world <registry-ip>:5043/test-hello:v2
    ```
    
4. Push the tagged container to the local registry using our local repository IP and port
    
    ```bash
    docker push <registry-ip>:5043/test-hello:v2
    ```
    
    ```
    Output:
    The push refers to repository [docker.example.net:5043/test-hello]
    baacf561cfff: Layer already exists
    unauthorized: authentication required
    ```
    

### 2- **Using testpush user (push and pull)**

1. Log in to the local docker registry **(type in the registry)** and enter the username and password
    
    ```bash
    docker logout <registry-ip>:5043
    docker login <registry-ip>:5043
    ```
    
2. Push the tagged container to the local registry using our local repository IP and port
    
    ```bash
    docker push <registry-ip>:5043/test-hello:v2
    ```
    
    ```
    Output:
    The push refers to repository [docker.example.net:5043/test-hello]
    baacf561cfff: Layer already exists
    v10: digest: sha256:acaddd9ed544f7baf3373064064a51250b14cfe3ec604d65765a53da5958e5f5 size: 528
    ```
    
    This should successfully push the image to the local repository.
    

### 3- Pulling Images from the local registry

**Now we need to test pulling container images from our local registry**

1. Remove the existing hello-world image pulled from the docker hub to make sure that we pull the image from our local repository
    
    ```bash
    ## to list the docker images
    docker image ls
    ## Remove the hello-world image locally using the image id
    docker image rm -f <image id>
    ```
    
2. Pull the my-hello-world image pushed locally to our local registry
    
    ```bash
    docker pull <registry-ip>:5043/test-hello:v2
    ## to list the docker images
    docker image ls
    ```
    

## List the local registry Images using CLI

```bash
sudo apt install jq
```

To list the current images in the local repository

```bash
curl -s -u test:password https://<registry-ip>:5043/v2/_catalog | jq
```

To list the tags of a specific image in the local repository

```bash
curl -s -u test:password https://<registry-ip>:5043/v2/test-hello/tags/list | jq
```

## UI local Docker registry

Testing the UI docker registry on the desktop, log in on the Docker Registry UI by visiting the webpage [https://<registry-ip](http://docker.webalo.net/)[>](http://8.208.91.39:8086/)

You have to authenticate with the credentials then we can list and access all the images in our local registry and pull images.