[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline\_service\_pe-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-pe)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-pe)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-pe)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-pe)](./LICENSE)
# PE Service

This service extracts attributes (imports, exports, section names, ...) from windows PE files using the python library LIEF.

This is a replacement for the original PEFile service of AssemblyLine.

# Dependencies
This service uses the LIEF library.
It also downloads the latest version of the Rich Header compiler information from https://github.com/dishather/richprint/blob/master/comp_id.txt
And the latest version of MalwareBazaar's Code Signing Certificate Blocklist from https://bazaar.abuse.ch/export/csv/cscb/
When building the docker container.

It also incorporate the ordlookup files from https://github.com/erocarrera/pefile/tree/master/ordlookup
And the statically built c release of https://github.com/NextronSystems/gimphash
Those last two are statically built in the module and may need to be updated once in a while.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name PE \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-pe

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service PE

Ce service extrait les information (imports, exports, noms de sections, ...) des executables windows en utilisant la librairie LIEF.

Ceci est un remplacement direct pour le service original d'Assemblyline nommé PEFile.

# Dépendances
Ce service utilise la librarie LIEF.
Ce service télécharge aussi la dernière version du `Rich Header compiler information` provenant de https://github.com/dishather/richprint/blob/master/comp_id.txt
Ainsi que la dernière version du `Code Signing Certificate Blocklist` de MalwareBazaar provenant de https://bazaar.abuse.ch/export/csv/cscb/
Lors que l'image docker est construite.

Ce service comprend aussi les fichier composant l'outil ordlookup provenant de https://github.com/erocarrera/pefile/tree/master/ordlookup
Ainsi qu'une version statiquement compilée de https://github.com/NextronSystems/gimphash en C
Ces deux derniers sont statiquement compilés dans le module et devraient être mises à jour périodiquement.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name PE \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-pe

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
