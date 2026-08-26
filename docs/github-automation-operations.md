# Operación de self-hosted-ci

Este documento vive en el repositorio independiente `self-hosted-ci` y describe su superficie operativa.

## Principio de activación

La plataforma permanece inerte salvo que exista autoridad externa explícita y verificable para el repositorio, organización, runner group, GitHub App, claves y host involucrados.

## Comandos locales

```bash
make setup
make test
make validate
make evidence
make status
```

## Incorporar un repositorio

1. Autorizar explícitamente la cuenta u organización y el repositorio.
2. Registrar el repositorio y su política en un archivo privado que valide contra
   el schema del proyecto, por ejemplo `registry/repositories.local.json`.
3. Instalar la GitHub App sólo en el alcance aprobado.
4. Configurar el required check y el runner group correspondiente.
5. Ejecutar la suite externa y adjuntar evidencia antes de habilitar el routing local.

## Volver a GitHub-hosted

Deshabilitar el routing local del repositorio en el registry. La coordinación debe fallar cerrada y utilizar exclusivamente la ruta GitHub-hosted; nunca debe aceptar una ejecución local histórica o no autorizada.

## Evidencia

Los resultados reproducibles se generan localmente bajo `evidence/`, que ignora
todo salvo su README. `scripts/validate-github-automation.py` valida schemas,
hashes, selectores, matriz y límites de autoridad antes de aceptar un snapshot.
El snapshot real se archiva en almacenamiento privado y no se publica junto al
código.
