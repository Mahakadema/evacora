# evacora
evacora is a stateless password manager. It calculates passwords on the fly, using the information you provide along with your master password. Your passwords are never stored anywhere. Because passwords are never stored you also don't need to sync them, meaning you don't have to send them to a cloud, and don't have to sync files between devices.

## How to use evacora
You can use evacora by running the CLI with nodeJS or by using the [web version](https://mahakadema.github.io/evacora). The CLI runs faster and allows for local storage of accounts and password checking for your master password.

To generate a password, enter a service name and master password. A username can be used to manage multiple accounts. A salt can be specified to change the generated password, which can be used for password resets.

To use the CLI, download the latest release zip, unzip the file and run node inside the directory.

In the CLI, the parameters are specified via flags.
- `-n <name>` The service name, may not contain spaces
- `-p <password>` The password, may not contain spaces
- `-u <username>` A username or alias, defaults to "null"
- `-s <salt>` A salt, defaults to an empty string
- `-l <length>` The length of the resulting password, defaults to 30
- `-c` Copies the password into the clipboard for 15 seconds, instead of printing it into the console

The input `node . -n example.com -u admin -p password1 -l 45` will generate a 45 character long password for `admin@example.com`

Additionally, the file path in `dataLocation` at the top of `index.js` may point towards a JSON file containing information on the registered accounts. An example file can be found in this repository.
If the supplied username matches any of the aliases of the registered accounts for the service, the full name of the account is automatically selected.
If no username is supplied and a file can be found, all users registered for the supplied service will have their password returned.
If a user from the file is used, their stored `salt` and `length` settings override the flags set in the command.
The file may contain an argon2id hash of the master password. If this field is set to `"null"`, a hash of the master password will be generated for you to fill into the field. Afterwards, only the correct master password will be accepted to avoid typos.

For example, the input `node . -n example.com -p password1 -l 20`, with the example file, will generate two passwords: one for `admin@example.com` of length `45` and with salt `abc`, and one for `second-account@example.com` of length `25` and with no salt.

## No storage does not mean zero risk
Just because evacora does not require you to store your passwords anywhere does not mean you cannot have your passwords stolen. You will most likely copy the password to your clipboard to log into the service. Therefore any application able to read your clipboard may read out the passwords. An open website may read your clipboard if you focus the tab, any browser extentions may read your clipboard and any application running on your machine with sufficient permissions may read your keystrokes, allowing it to even read out your master password. It is therefore advised to never use evacora on machines you do not trust, to clear the clipboard after you logged in (and to disable clipboard history), and to make sure you trust your browser addons.
