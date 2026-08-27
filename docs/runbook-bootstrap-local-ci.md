# Bootstrap de CI local (sandbox)

Este runbook describe cómo preparar el host local sin activar CI por accidente.
El diseño es hosted-by-default: sólo un repositorio explícitamente autorizado
puede pedir CI local y todos los demás continúan en GitHub-hosted.

## Estado y límites

El health supervisor Windows/WSL es independiente del runner. Publica un
snapshot observable por SFTP, pero no registra runners, no ejecuta código de
pull requests y no habilita el runtime JIT.

El contrato JIT, el ledger de lifecycle y el perfil Incus están versionados,
pero el broker operativo, la instalación/configuración de Incus y GARM, la
policy de egress activable, la configuración host-specific de la GitHub App y
la evidencia firmada de un host real no forman parte del repositorio ni se
activan por instalar este release. Mientras falte cualquiera,
la ejecución local permanece bloqueada.

La implementación no usa Cloudflare ni Workers. `scripts/check-local-only.py`
bloquea su reintroducción y se ejecuta mediante `make distribution-check`.

## Prerrequisitos

Se requiere una distro WSL2 dedicada `Ubuntu-24.04-CI`, propiedad de una cuenta
de servicio no administrativa; PowerShell local elevado; Ubuntu 24.04 con
systemd; un repositorio sandbox seleccionado; una GitHub App instalada sólo en
ese alcance; secretos fuera del repositorio; y evidencia host-specific de
Incus, GARM, imagen, ownership, ACLs y red, firmada por el reviewer autorizado.

No copiar secretos, claves privadas, inventarios ni identificadores del host al
repositorio público.

## Health en Windows

Ejecutar primero el plan. No crea cuentas, no muta WSL, no registra tareas ni
llama a GitHub:

```powershell
Set-Location C:\ProgramData\self-hosted-ci\package\scripts\host
& .\install-health-prerequisites.ps1 `
  -ExpectedServiceAccountSid '<SID-from-local-inventory>' `
  -AuthorizedKey '<public-health-key>'
```

Aplicar sólo después de revisar el plan:

```powershell
& .\install-health-prerequisites.ps1 `
  -ExpectedServiceAccountSid '<SID-from-local-inventory>' `
  -AuthorizedKey '<public-health-key>' `
  -Apply `
  -AcknowledgeCreateDisabledReader `
  -AcknowledgeOneTimePasswordRotation
```

Esperar `status: installed`, dos heartbeats distintos, tarea one-shot ausente,
credencial temporal invalidada y `runner_registration_changed: false`.

Después instalar el supervisor persistente:

```powershell
& .\install-health-supervisor.ps1 `
  -ExpectedServiceAccountSid '<SID-from-local-inventory>' `
  -ReaderAccount '<host>\\selfhosted-ci-health' `
  -Apply `
  -AcknowledgePersistentPasswordTask `
  -AcknowledgeServiceAccountPasswordRotation `
  -AcknowledgeProtectedHealthAcls
```

Validar desde la Mac con `scripts/host/check-self-hosted-ci-health.sh`. Debe
devolver `0`. Un snapshot inválido, vencido o cruzado de identidad sólo vuelve
al sistema no elegible; nunca otorga permiso implícito para ejecutar CI.

## Runtime JIT

### Prerrequisitos Incus y GARM

El instalador Windows es plan-only por defecto. El plan valida la cuenta de
servicio, SID, distro y pins; no rota credenciales, no instala paquetes y no
registra runners:

```powershell
& .\install-jit-prerequisites.ps1 `
  -ExpectedServiceAccountSid '<SID-from-local-inventory>' `
  -IncusVersion '6.0.0-1ubuntu0.3'
```

Apply exige ambos acknowledgements:

```powershell
& .\install-jit-prerequisites.ps1 `
  -ExpectedServiceAccountSid '<SID-from-local-inventory>' `
  -IncusVersion '6.0.0-1ubuntu0.3' `
  -Apply `
  -AcknowledgeHostPackageInstallation `
  -AcknowledgeOneTimePasswordRotation
```

El instalador transmite el payload completo a una unidad transitoria systemd,
lo decodifica en `/run`, verifica su SHA-256 y `bash -n`, y recién entonces lo
ejecuta. La unidad tiene deadline propio y `KillMode=control-group`. Apply
instala la versión Incus fijada por política y GARM 0.2.1 con hash de release
fijado, crea `garm-manager` bloqueado/no administrativo y deja GARM deshabilitado.
No instala credenciales GitHub, no crea pools y no registra runners.

Una ejecución exitosa termina con `status: installed`, task one-shot ausente,
credencial almacenada invalidada, `garm_enabled: false` y
`runner_registration_performed: false`. Un fallo puede dejar prerequisitos WSL
parcialmente instalados; el reintento reconcilia pins y postcondiciones de forma
idempotente, pero el mensaje sólo afirma rollback de task, credencial y staging
Windows, no un rollback ficticio de paquetes Linux.

### Contrato y evidencia

El provisionador es plan-only por defecto:

```bash
scripts/host/provision-wsl-jit-contract.sh --plan
```

Antes de aplicar se deben completar y revisar, en el WSL dedicado:

1. Incus pineado, con pool dedicado y red `ci-jit-isolated`.
2. Perfil no privilegiado basado en `templates/incus/runner-profile.yaml`.
3. Usuario `garm-manager` sin grupos administrativos y con acceso sólo al
   provider Incus necesario.
4. GARM pineado, con secretos desde un store externo.
5. Egress default-deny/proxy-only cargado antes del registro y probado después
   de reboot. Los units de red actuales ejecutan `/usr/bin/false` y deben ser
   reemplazados por una implementación auditada.
6. Bundle `runner-boundary-v2` con hashes, ownership, modes, policy y
   attestation verificados.

Recolectar y validar evidencia sin activar nada:

```bash
python3 scripts/host/collect-wsl-jit-measurements.py \
  --input <boundary-template.json> --output <boundary-v2.json> \
  --measurement-root <host-evidence>
python3 scripts/host/verify-wsl-jit-readiness.py \
  --evidence <boundary-v2.json> --measurement-root <host-evidence> \
  --reviewer-public-key <reviewer-public-key.pem> \
  --pinned-fingerprint <reviewer-fingerprint>
```

Sólo salida `0` pasa al gate. `2` es evidencia inválida y `3` evidencia válida
pero bloqueada. El `--apply` instala contratos y mantiene GARM disabled; la
activación posterior requiere una ceremonia independiente y
`ACTIVATION_APPROVED`.

## Sandbox y GitHub App

La registry es hosted-by-default. El sandbox es el único candidato inicial;
su entrada local debe incluir `local-with-github-fallback`, autoridad exacta,
installation ID, runner group restringido cuando corresponda y execution trust.
La App debe tener permisos mínimos y nunca compartir identidad con el reviewer.

El runtime futuro debe hacer polling outbound, pedir JIT para repo y SHA exactos,
crear un container efímero no privilegiado, aceptar exactamente un job y
destruirlo en success, failure, cancel, timeout, force-cancel y reboot. Debe
registrar cleanup durable y cero runners, tokens o containers huérfanos.

El broker, el endpoint JIT operativo y el lifecycle Incus real siguen
pendientes. Hasta cerrarlos, ningún workflow debe usar `runs-on` local.

## Reintento, rollback y vuelta a GitHub-hosted

Los instaladores son plan-only por defecto y validan postcondiciones exactas.
Tras un fallo, confirmar que tarea, staging, credenciales temporales y artifacts
administrados quedaron limpios antes de reintentar. No desregistrar la distro
personal ni borrar su export.

Para retirar health: primero `uninstall-health-supervisor.ps1`, luego
`uninstall-health-prerequisites.ps1`; verificar tarea, snapshot, control, reader
y los cuatro archivos Linux ausentes.

Para desactivar CI local, quitar el repositorio de la allowlist, revocar la
autoridad exacta de la App/runner group y conservar el workflow GitHub-hosted.
La configuración ausente o inválida debe elegir GitHub-hosted y no una ejecución
local histórica.

## Verificación final

```bash
make setup
make test
make validate
make distribution-check
```

Conservar fuera del repositorio la evidencia de instalación, boundary, policy
post-reboot, lifecycle completo, cleanup, autoridad de App/runner, fallback y
rollback. Si falta evidencia independiente de cualquier gate, el resultado es
GitHub-hosted y el runtime local permanece desactivado.
