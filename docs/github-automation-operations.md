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

## Interfaz para agentes locales

Codex y Claude Code comparten una única skill y la misma CLI determinista. La
skill sólo traduce lenguaje natural; `self-hosted-ci` valida el repositorio
exacto, consulta autoridad/health y persiste el routing privado con auditoría.

```bash
self-hosted-ci status [OWNER/REPO]
self-hosted-ci doctor [OWNER/REPO]
self-hosted-ci run-local [OWNER/REPO] --pr 123
self-hosted-ci run-local [OWNER/REPO] --pr 123 --apply
self-hosted-ci use-local [OWNER/REPO]
self-hosted-ci use-local [OWNER/REPO] --apply
self-hosted-ci use-github [OWNER/REPO]
self-hosted-ci use-github [OWNER/REPO] --apply
```

Si se omite `OWNER/REPO`, la CLI resuelve el remote `origin` del checkout
actual. Las mutaciones son plan-only sin `--apply`. `run-local` autoriza sólo
el PR/head exacto resuelto por el control plane y nunca cambia el routing
persistente. `use-local` exige que la GitHub App del host ya esté instalada con
selección exacta para ese repositorio; no amplía instalaciones ni acepta
wildcards. `use-github` elimina primero el workflow administrado y recién
después registra GitHub-hosted como estado privado efectivo.

El registry y audit log operativos viven fuera del repositorio público, bajo
`~/.config/self-hosted-ci/operator/`, con permisos `0700/0600`. No contienen
claves privadas ni tokens. La instalación de las interfaces globales se hace
desde un checkout fijado a un commit revisado:

```bash
python3 scripts/install-agent-interfaces.py \
  --ssh-target selfhosted-ci-svc@HOST \
  --ssh-key ~/.local/share/self-hosted-ci/service-ssh/id_ed25519 \
  --public-sha <reviewed-40-character-commit>
```

El instalador enlaza la fuente canónica de `skills/self-hosted-ci` en
`~/.codex/skills/self-hosted-ci` y `~/.claude/skills/self-hosted-ci`, e instala
`self-hosted-ci` en `~/.local/bin`. Claude Code local expone además
`/self-hosted-ci`; Codex expone `$self-hosted-ci`. Ambos pueden descubrirla por
las frases naturales descriptas en la skill.

## Incorporar un repositorio

1. Autorizar explícitamente la cuenta u organización y el repositorio.
2. Registrar el repositorio y su política en un archivo privado que valide contra
   el schema del proyecto, por ejemplo `registry/repositories.local.json`.
3. Instalar la GitHub App sólo en el alcance aprobado.
4. Configurar el required check y el runner group correspondiente.
5. Ejecutar la suite externa y adjuntar evidencia antes de habilitar el routing local.

`self-hosted-ci use-local OWNER/REPO --apply` automatiza únicamente el tramo
que ya puede probar de punta a punta: autoridad exacta preexistente, host
saludable, instalación idempotente del workflow JIT fijado por SHA y registro
privado. Si falta autoridad seleccionada devuelve
`selected_repository_authority_missing`; el agente debe instalar/seleccionar
la GitHub App sólo para ese repo y reanudar. Un plan bloqueado nunca se registra
como local.

## Volver a GitHub-hosted

Deshabilitar el routing local del repositorio en el registry. La coordinación debe fallar cerrada y utilizar exclusivamente la ruta GitHub-hosted; nunca debe aceptar una ejecución local histórica o no autorizada.

## Evidencia

Los resultados reproducibles se generan localmente bajo `evidence/`, que ignora
todo salvo su README. `scripts/validate-github-automation.py` valida schemas,
hashes, selectores, matriz y límites de autoridad antes de aceptar un snapshot.
El snapshot real se archiva en almacenamiento privado y no se publica junto al
código.
