import yaml, havesxs, uuid, hashlib

PUBLIC_KEY_TOKEN = "31bf3856ad364e35"

class Update:
    def __init__(
        self,
        target_component,
        target_arch,
        version,
        copyright,
        registry_keys=None,
        version_scope="nonSxS",
    ):
        self.identifier = hashlib.sha1(str(uuid.uuid4()).encode('ascii')).hexdigest()
        self.target_component = target_component
        self.target_arch = target_arch
        self.version = version
        self.copyright = copyright
        self.registry_keys = registry_keys
        self.version_scope = version_scope
        self.public_key_token = PUBLIC_KEY_TOKEN

    def generate_component_sxs(self):
        return havesxs.generate_sxs_name(
            {
                "name": self.target_component,
                "culture": "none",
                "version": self.version,
                "publicKeyToken": self.public_key_token,
                "processorArchitecture": self.target_arch,
                "versionScope": self.version_scope,
            }
        )

    def generate_component_manifest(self):
        registry_entries = []
        if self.registry_keys:
            registry_values = []
            for registry_key in self.registry_keys:
                for registry_value in registry_key['values']:
                    registry_values.append(f"""<registryValue name="{registry_value['key']}" valueType="{registry_value['type']}" value="{registry_value['value']}" />""")
                registry_values = '\n'.join(registry_values)
                registry_entries.append(f"""<registryKey keyName="{registry_key['key_name']}" perUserVirtualization="{'Enable' if registry_key['perUserVirtualization'] else 'Disable'}">{registry_values}</registryKey>""")
        registry_entries = "<registryKeys>" + "".join(registry_entries) + "</registryKeys>" if registry_entries else ""
        return f"""<?xml version="1.0" encoding="utf-8" standalone="yes"?><assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0" copyright="{self.copyright}"><assemblyIdentity name="{self.target_component}" version="{self.version}" processorArchitecture="{self.target_arch}" language="neutral" buildType="release" publicKeyToken="{self.public_key_token}" versionScope="{self.version_scope}" />{registry_entries}</assembly>"""

    def generate_update_sxs(self):
        return havesxs.generate_sxs_name(
            {
                "name": self.identifier,
                "culture": "none",
                "version": self.version,
                "publicKeyToken": self.public_key_token,
                "processorArchitecture": self.target_arch,
                "versionScope": self.version_scope,
            }
        )

    def generate_update_manifest(self):
        return f"""<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"
    copyright="{self.copyright}">
    <assemblyIdentity name="{self.identifier}" version="{self.version}"
        processorArchitecture="{self.target_arch}" language="neutral"
        buildType="release" publicKeyToken="{self.public_key_token}"
        versionScope="{self.version_scope}" />
    <deployment xmlns="urn:schemas-microsoft-com:asm.v3" />
    <dependency discoverable="false">
        <dependentAssembly dependencyType="install">
            <assemblyIdentity name="{self.target_component}" version="{self.version}"
                processorArchitecture="{self.target_arch}" language="neutral"
                buildType="release" publicKeyToken="{self.public_key_token}"
                versionScope="{self.version_scope}" />
        </dependentAssembly>
    </dependency>
</assembly>"""


class MasterUpdateManifest:
    def __init__(self, package, copyright, version, target_arch, updates):
        self.package = package
        self.copyright = copyright
        self.version = version
        self.target_arch = target_arch
        self.public_key_token = PUBLIC_KEY_TOKEN

        self.updates = updates

    def generate_mum(self):
        mum = f"""<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v3" manifestVersion="1.0"
    copyright="{self.copyright}">
<assemblyIdentity name="{self.package}" version="{self.version}"
    processorArchitecture="{self.target_arch}" language="neutral" buildType="release"
    publicKeyToken="{self.public_key_token}" />
<package identifier="{self.package}" releaseType="Feature Pack">
"""
        mum += "\n".join(list(map(self.generate_mum_update, self.updates)))
        mum += "\n</package>\n</assembly>"
        return mum

    def generate_mum_update(self, update):
        return f"""<update name="{update.identifier}">
    <component>
        <assemblyIdentity name="{update.identifier}" version="{update.version}"
            processorArchitecture="{update.target_arch}" language="neutral"
            buildType="release" publicKeyToken="{update.public_key_token}"
            versionScope="{update.version_scope}" />
    </component>
</update>"""


with open("cfg.yaml", "r") as f:
    config = yaml.safe_load(f)

staged_updates = []
staged_files = ["update.mum", "update.cat"]
for update in config["updates"]:
    update = Update(**update, copyright=config["copyright"])
    component_sxs = update.generate_component_sxs()
    update_sxs = update.generate_update_sxs()
    with open(f".\\{component_sxs}.manifest", "w+") as f:
        f.write(update.generate_component_manifest())
    with open(f".\\{update_sxs}.manifest", "w+") as f:
        f.write(update.generate_update_manifest())
    staged_updates.append(update)
    staged_files.extend([f"{component_sxs}.manifest", f"{update_sxs}.manifest"])

with open(".\\update.mum", "w+") as f:
    f.write(
        MasterUpdateManifest(
            config["package"],
            config["copyright"],
            config["version"],
            config["target_arch"],
            staged_updates,
        ).generate_mum()
    )

with open(".\\files.txt", "w+") as f:
    f.write("\n".join(staged_files))

with open(".\\update.cdf", "w+") as f:
    f.write("""[CatalogHeader]
Name=update.cat
ResultDir=.\\
CatalogVersion=2
HashAlgorithms=SHA256

[CatalogFiles]
""")
    for (i, filename) in enumerate(filter(lambda f: f != "update.cat", staged_files)):
        f.write(f"<HASH>F{i+1}={filename}\n")

with open(".\\build.bat", "w+") as f:
    f.write(f"""@echo off
set CAB_NAME={config['package']}31bf3856ad364e35{config['target_arch']}{config['version']}.cab

del /f update.cat 2>NUL
del /f *.cab 2>NUL
bin\makecat update.cdf || exit /b 1
bin\signtool.exe sign /f sxs.pfx /p 1 /fd SHA256 update.cat || exit /b 1
bin\makecab /d "CabinetName1=%CAB_NAME%" /f files.txt || exit /b 1
del /f setup.* 2>NUL
bin\signtool.exe sign /f sxs.pfx /p 1 /fd SHA256 disk1\%CAB_NAME% || exit /b 1
copy disk1\*.cab . >NUL""")