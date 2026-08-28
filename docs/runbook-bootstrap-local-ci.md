# Bootstrap de CI local (sandbox)

Este runbook describe cómo preparar el host local sin activar CI por accidente.
El diseño es hosted-by-default: sólo un repositorio explícitamente autorizado
puede pedir CI local y todos los demás continúan en GitHub-hosted.

## Estado y límites

El health supervisor Windows/WSL es independiente del runner. Publica un
snapshot observable por SFTP, pero no registra runners, no ejecuta código de
pull requests y no habilita el runtime JIT.

El contrato JIT, el ledger de lifecycle y el perfil Incus están versionados.
Los instaladores reproducibles pueden dejar Incus y GARM instalados pero
inertes, y pueden crear el límite Incus aislado sin instancias. El broker
operativo, la policy de egress activable, la configuración host-specific de la GitHub App y
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
  -ReaderAccount '<host>\selfhosted-ci-health' `
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
fijado. También instala explícitamente `dnsmasq-base`, que aporta el ejecutable
necesario para los bridges administrados por Incus, sin instalar ni habilitar el
servicio persistente `dnsmasq`. Crea `garm-manager` bloqueado/no administrativo y deja GARM deshabilitado.
No instala credenciales GitHub, no crea pools y no registra runners.

Una ejecución exitosa termina con `status: installed`, task one-shot ausente,
credencial almacenada invalidada, `garm_enabled: false` y
`runner_registration_performed: false`. Un fallo puede dejar prerequisitos WSL
parcialmente instalados; el reintento reconcilia pins y postcondiciones de forma
idempotente, pero el mensaje sólo afirma rollback de task, credencial y staging
Windows, no un rollback ficticio de paquetes Linux.

### Límite Incus inerte

Después de instalar los prerrequisitos, inspeccionar primero el plan:

```powershell
& .\install-incus-boundary.ps1 `
  -ExpectedServiceAccountSid '<SID-from-local-inventory>'
```

Apply requiere dos acknowledgements separados:

```powershell
& .\install-incus-boundary.ps1 `
  -ExpectedServiceAccountSid '<SID-from-local-inventory>' `
  -Apply `
  -AcknowledgeIncusBoundaryMutation `
  -AcknowledgeOneTimePasswordRotation
```

Este paso inicializa Incus una sola vez si su base todavía no existe y crea
únicamente `ci-jit`, el pool `dir` sobre un filesystem ext4 loop-backed
`ci-jit-dedicated`, el bridge host-only `ci-jit-isolated` sobre
`10.254.0.1/28`, con una única lease DHCP (`10.254.0.2`), gateway local
anunciado pero no enrutable, y sin uplink,
NAT ni IPv6, y el perfil `ci-jit`. El proyecto queda
`restricted`, limitado a un container/una instancia, 2 CPU, 4 GiB de memoria,
2048 procesos y un volumen root de 12 GiB dentro de un pool cuyo loop file
tiene un máximo agregado de 16 GiB. El perfil exige container no privilegiado,
idmap aislado, nesting deshabilitado y exactamente un disco root más una NIC
conectada al bridge aislado.

El filesystem ext4 se monta mediante una unidad `.mount` de systemd —no por
`fstab`— con project quotas y un drop-in que impide iniciar Incus sin ese mount.
Antes de terminar, el instalador prueba la cuota con escrituras reales en un
volumen temporal y ejecuta cuatro canarios negativos sin imagen ni salida
externa: container privilegiado, nesting, idmap no aislado y dispositivo proxy.
Los cuatro deben ser rechazados por la
policy; el cleanup debe volver a demostrar cero instancias y cero volúmenes.

El resultado correcto informa `project_restricted: true`,
`project_instance_limit: 1`, `instances: 0`, `bridge_uplink: false`, NAT false,
`storage_driver: dir`, `storage_filesystem: ext4`,
`storage_pool_size: 16GiB`, `storage_quota_canary_passed: true`,
`negative_canaries_passed: true`, `external_services_configured: false`, task one-shot ausente y credencial
temporal invalidada. Este paso no configura GitHub, no habilita GARM, no crea
containers y no registra runners. Si falla, conserva diagnóstico sanitizado en
`C:\ProgramData\self-hosted-ci\diagnostics\incus-boundary`; el reintento es
idempotente y nunca reinicializa una base Incus existente.

### Contrato y evidencia

El provisionador es plan-only por defecto:

```bash
scripts/host/provision-wsl-jit-contract.sh --plan
```

Antes de aplicar se deben completar y revisar, en el WSL dedicado:

1. Incus pineado, con proyecto restringido, pool dedicado y red
   `ci-jit-isolated`, verificados por `install-incus-boundary.ps1`.
2. Perfil no privilegiado basado en `templates/incus/runner-profile.yaml`.
3. Usuario `garm-manager` sin grupos administrativos y con acceso sólo al
   provider Incus necesario. `provision-wsl-jit-contract.sh --apply` instala
   una identidad TLS `root:garm-manager` `0640`, restringida por Incus al
   proyecto `ci-jit`, sobre `https://127.0.0.1:8443`; valida que `default` y
   una creación privilegiada sean rechazados. No usa el socket Unix ni el
   grupo `incus-admin`, y no habilita GARM ni registra runners.
4. GARM pineado, con secretos desde un store externo.
5. Cuarentena default-deny instalada con `systemctl enable --now` antes de
   cualquier rama de activación. Su unit tiene `DefaultDependencies=no`, corre
   después de `local-fs.target` y antes de `incus.service`, de modo que persiste
   después de reboot sin una ventana de red abierta. La activación reemplaza
   atómicamente esa cuarentena por la policy proxy-only,
   permite desde el bridge sólo DHCP y los proxies locales, bloquea forwarding,
   limita Squid a `CONNECT` 443 contra la allowlist y expone un callback proxy
   acotado a metadata y callbacks GARM. Los units siguen gateados por
   `ACTIVATION_APPROVED` y permanecen deshabilitados hasta la transacción de
   activación.
6. Bundle `runner-boundary-v2` con hashes, ownership, modes, policy y
   attestation verificados. Apply copia atómicamente sólo los artefactos
   referenciados por ese bundle a `/etc/self-hosted-ci/host-evidence` y el
   bundle a `/etc/self-hosted-ci/runner-boundary-v2.json`; rechaza symlinks,
   referencias extra, traversal y evidencia no perteneciente a root. No copia
   claves privadas ni otros archivos vecinos del directorio de mediciones. El
   bundle debe incluir además `live/live-artifacts-v1.json` y las copias
   medidas de scripts, units y configuraciones públicas que serán instaladas.
   Ese manifiesto también fija los hashes de `garm`, `garm-cli` y el provider.
   Excluye deliberadamente secretos, certificados, claves y el `config.toml`
   materializado de GARM.
7. El payload **final** firmado de `runner-boundary-v2` contiene la autorización
   canary Ed25519 y el proof set de seis escenarios. Este requisito no se
   fabrica durante el bootstrap inerte: se completa después de configurar GARM
   con inventario cero y ejecutar la matriz canary descrita más abajo. Cada proof liga nonce,
   authorization digest, repo/SHA, allocation, scale set, run/job, receipts y
   cleanup global. También en reboot debe existir exactamente un job reclamado
   (`jobs_started=1`) con `started_at`; cero jobs ya no constituye evidencia.
   El evaluator deriva desde esos proofs cualquier vista legacy
   necesaria; `host_security` ya no acepta `runner_lifecycle_runs` booleanos.

Una vez terminada la matriz canary y ensamblado su proof set, recolectar y
validar la evidencia final sin activar producción:

```bash
sudo python3 scripts/host/stage-wsl-jit-live-contract.py \
  --input-boundary <boundary-template.json> \
  --output-boundary <boundary-with-live-contract.json> \
  --measurement-root <host-evidence>
python3 scripts/host/collect-wsl-jit-measurements.py \
  --input <boundary-with-live-contract.json> --output <boundary-measured.json> \
  --measurement-root <host-evidence>
python3 scripts/host/sign-wsl-jit-boundary.py \
  --input <boundary-measured.json> --output <boundary-v2.json> \
  --reviewer-private-key </absolute/path/outside/repo/reviewer-private-key.pem>
python3 scripts/host/verify-wsl-jit-readiness.py \
  --evidence <boundary-v2.json> --measurement-root <host-evidence> \
  --reviewer-public-key <reviewer-public-key.pem> \
  --pinned-fingerprint <reviewer-fingerprint>
```

La clave privada debe ser Ed25519, vivir fuera del checkout y no tener permisos
de grupo/mundo (por ejemplo `0600`). El firmador rechaza bundles ya firmados y
nunca modifica el archivo medido de entrada; escribe la salida canónica de forma
atómica. Sólo la clave pública y su fingerprint se usan después para verificar
y provisionar.

Sólo salida `0` pasa al gate. `2` es evidencia inválida y `3` evidencia válida
pero bloqueada. El `--apply` instala contratos y mantiene GARM disabled; la
activación posterior requiere una ceremonia independiente y
`ACTIVATION_APPROVED`. Provisioning recalcula el contrato después de instalar;
activation y los `ExecStartPre` de boundary, network policy, proxy y GARM lo
revalidan otra vez. Cualquier cambio de bytes, owner, group, mode, hardlink o
symlink bloquea el arranque.

Los comandos de live contract que siguen pertenecen a la fase final: no
ejecutarlos durante el bootstrap inerte ni antes de obtener los seis proofs
canary. En Windows, la instalación o actualización reproducible usa un bundle tar
público dentro de `C:\ProgramData\self-hosted-ci\package`. El tar debe preservar
owner/mode Unix y contener un único árbol `contract/` con:

- `runner-boundary-template-v2.json`;
- `runner-boundary-v2.json`, ya firmado por el reviewer independiente;
- `reviewer-public-key.pem` y `reviewer-key.sha256`;
- todos los refs relativos medidos por el bundle (por ejemplo `evidence/` y
  `live/`).

El wrapper vuelve a ejecutar staging y collection dentro de
`Ubuntu-24.04-CI`, exige igualdad canónica con el contenido firmado, verifica y
recién entonces provisiona. No recibe claves privadas, no habilita GARM, no
configura GitHub y no crea ni modifica `outbound-worker.runtime-ready`.

Desde una PowerShell elevada, primero inspeccioná el plan:

```powershell
& .\install-wsl-jit-live-contract.ps1 `
  -ExpectedServiceAccountSid "<SID-exacto>"
```

Aplicá el mismo bundle content-addressed con los dos acknowledgements:

```powershell
& .\install-wsl-jit-live-contract.ps1 `
  -ExpectedServiceAccountSid "<SID-exacto>" `
  -Apply `
  -AcknowledgeLiveContractMutation `
  -AcknowledgeOneTimePasswordRotation
```

El bundle por defecto es
`artifacts/live-contract/live-contract-bundle.tar`; `-BundleRelativePath`
permite otro path relativo seguro dentro de `package`. En éxito, la tarea
Password/LUA, su credencial almacenada y el staging desaparecen. En falla, el
wrapper rota otra vez la contraseña y conserva diagnóstico público versionado
en `C:\ProgramData\self-hosted-ci\diagnostics\live-contract-install\v1`.

Aplicar el contrato únicamente con evidencia verificada y la clave pública del
reviewer (nunca con su clave privada):

```bash
sudo scripts/host/provision-wsl-jit-contract.sh --apply \
  --evidence <boundary-v2.json> \
  --reviewer-public-key <reviewer-public-key.pem> \
  --reviewer-key-fingerprint <sha256-hex> \
  --acknowledge-host-mutation \
  --acknowledge-dedicated-boundary
```

La imagen del runner se prepara en una transacción separada, antes de tocar la
base de GARM. Elegí un remote y ref explícitos, consultá su fingerprint y
guardalo como un SHA-256 lowercase de 64 caracteres (no dependas de volver a
resolver el alias remoto más tarde):

```bash
incus image info images:ubuntu/24.04/cloud --format json | \
  python3 -c 'import json,sys; print(json.load(sys.stdin)["fingerprint"])'
```

El plan no consulta el remote ni modifica el host:

```bash
sudo /usr/local/lib/self-hosted-ci/prepare-incus-runner-image.sh --plan \
  --source-remote images \
  --source-ref ubuntu/24.04/cloud \
  --expected-fingerprint <64-hex-sha256> \
  --local-alias runner-ubuntu-24.04-pinned
```

Aplicá exactamente el mismo origen, fingerprint y alias:

```bash
sudo /usr/local/lib/self-hosted-ci/prepare-incus-runner-image.sh --apply \
  --source-remote images \
  --source-ref ubuntu/24.04/cloud \
  --expected-fingerprint <64-hex-sha256> \
  --local-alias runner-ubuntu-24.04-pinned \
  --acknowledge-remote-image-fetch \
  --acknowledge-local-image-alias-mutation
```

El apply verifica primero que el ref todavía resuelva al fingerprint esperado
y copia por el fingerprint completo, no por el alias remoto mutable. Si el
alias local ya apunta a ese fingerprint, la operación es idempotente; si apunta
a cualquier otro, falla sin reemplazarlo. No usa `--reuse`, no copia aliases
remotos y no habilita auto-update. Si una postcondición falla, elimina solamente
el alias creado por esa ejecución; nunca borra una imagen que pudiera tener
otros consumidores. La salida exitosa confirma imagen de container `x86_64`,
fingerprint y mapping de alias exactos, con GARM apagado y cero registros de
runners.

La configuración de GARM es una transacción separada e inerte. Antes de
activarlo, crear fuera del repo siete archivos root-only (`0600`): el secreto
JWT, la passphrase de SQLite, el username/password del administrador GARM y tres
configuraciones GitHub App con tres PEM distintos.
El password se envía únicamente en el body de `POST /first-run` o del login
loopback; nunca aparece
en argv, variables de entorno ni logs. El bootstrap inicializa el controller de
forma idempotente: una respuesta `409 already initialized` es esperable en un
retry y luego se prueba el login con las credenciales root-only. El bearer se
valida como JWT `HS256`
administrador firmado por el secreto configurado, se renueva si falta o vence
en menos de cinco minutos y sólo existe en `/run/self-hosted-ci/garm-cli`
(`0700`, config `0600`), por lo que desaparece al reiniciar.

La entidad ya no se prepara a mano. El comando valida primero tres identidades:

- runner-manager: `Metadata: read`, `Actions: read`, `Administration: write`;
- dispatcher: `Metadata: read`, `Pull requests: read`, `Actions: write`;
- live-job verifier: `Metadata: read`, `Actions: read`.

Sus app IDs, installation IDs, rutas PEM y fingerprints SPKI-SHA256 deben ser
distintos. El configurador abre los tres PEM root-only, exige RSA de al menos
2048 bits y compara la clave pública real, por lo que copiar la misma clave a
otra ruta también bloquea el apply. GARM recibe únicamente
runner-manager; dispatcher queda reservado para `workflow_dispatch`; el
verificador nunca recibe permisos de escritura. Reutilizar una identidad o una
clave bloquea el apply.

El contrato del dispatcher también fija `default_branch=main`,
`workflow_id=ci-jit-canary-child.yml` y
`workflow_path=.github/workflows/ci-jit-canary-child.yml`. Es el mismo JSON
root-only que consume la canary para despachar y volver a leer el PR antes de
crear cada allocation; no existe una segunda configuración con permisos más
amplios.

Después reconcilia la credencial GitHub App exacta
`self-hosted-ci-sandbox-app`, crea o
actualiza el repo sandbox sin instalar webhooks y recién entonces deriva su UUID
desde GARM. `--entity-id` es opcional y sirve sólo como postcondición si ya se
conoce. Los tres archivos usan los contratos
`runner-manager-app.json.example`, `dispatcher-app.json.example` y
`live-job-verifier-app.json.example`; cada JSON y PEM debe ser root-only `0600`.

Primero revisar el plan:

```bash
sudo /usr/local/lib/self-hosted-ci/configure-garm-jit.sh --plan
```

Después materializar la configuración manteniendo inventario cero. Este comando
no recibe ni crea un scale set: sólo configura manager, provider, imagen,
entidad target y contrato del broker. El bootstrap actual acepta únicamente
`personal-repository`: usar `owner/repo` y omitir `--runner-group`. La autoridad
de organización requiere una implementación posterior y no debe improvisarse
con flags que este script rechaza:

```bash
sudo /usr/local/lib/self-hosted-ci/configure-garm-jit.sh --apply \
  --config-template /etc/self-hosted-ci/garm/config.toml.example \
  --jwt-secret-file /root/self-hosted-ci-secrets/garm-jwt \
  --database-passphrase-file /root/self-hosted-ci-secrets/garm-db-passphrase \
  --garm-admin-username-file /root/self-hosted-ci-secrets/garm-admin-username \
  --garm-admin-password-file /root/self-hosted-ci-secrets/garm-admin-password \
  --runner-manager-app-config-file /etc/self-hosted-ci/runner-manager-app.json \
  --dispatcher-app-config-file /etc/self-hosted-ci/dispatcher-app.json \
  --live-job-verifier-app-config-file /etc/self-hosted-ci/live-job-verifier-app.json \
  --garm-cli-home /run/self-hosted-ci/garm-cli \
  --authority-kind personal-repository \
  --entity-name <owner/repo> \
  --repository-id <github-numeric-repository-id> \
  --image-alias <local-pinned-alias> \
  --image-fingerprint <64-hex-sha256> \
  --allocation-authority-public-key /etc/self-hosted-ci/allocation-authority-public-key.pem \
  --live-job-verifier /usr/local/libexec/self-hosted-ci/github-live-job-verifier.py \
  --acknowledge-root-secret-installation \
  --acknowledge-garm-database-mutation \
  --acknowledge-external-github-configuration
```

Esta etapa verifica la imagen local por fingerprint, configura callback y
metadata directos en `10.254.0.1:8080`, e inyecta en el bootstrap del runner
`HTTP_PROXY`/`HTTPS_PROXY=http://10.254.0.1:3128` con
`NO_PROXY=10.254.0.1,127.0.0.1,localhost`. El bridge anuncia solamente su
gateway local, con routing y NAT desactivados; nftables mantiene el egress
default-deny.
GARM se inicia sólo en una unidad transitoria y esta fase exige cero scale sets
y cero instancias Incus: no se crea ni registra ningún runner. `health-state.json` se
escribe atómicamente desde el resultado real del API, incluyendo ID, nombre,
provider, imagen, label, autoridad y runner group; no es una declaración manual.
Si falla, config, health-state y la base SQLite vuelven a su versión anterior
después de detener la unidad transitoria; los recursos creados durante el intento
también se eliminan por API cuando todavía está disponible. Un corte entre esas
dos defensas sigue siendo retry-safe porque cada objeto se busca por identidad
exacta antes de crearlo o actualizarlo.

### Matriz lifecycle canary y ensamblado de evidencia

La configuración exitosa debe terminar con `zero_scale_sets: true`, GARM
inactivo y cero instancias. No crear un scale set manual ni conservar uno
deshabilitado: el broker crea un scale set efímero por escenario, permite un único job y
lo elimina antes de avanzar al siguiente. La autorización Ed25519 liga los seis
escenarios canónicos (`success`, `failure`, `cancel`, `timeout`,
`force-cancel`, `reboot`), `max_allocations: 6`, `max_concurrency: 1` y
`max_jobs_per_allocation: 1`.

Crear primero un template unsigned root-only `0600`. Debe contener el workflow,
repo, PR, base/head/merge/dispatch SHA, nonce y ventana temporal; los cuatro
digests live y el fingerprint del allocation signer pueden inicializarse con 64
ceros porque el assembler los reemplaza después de medir los archivos reales.
No copiar ni derivar otro JSON del dispatcher: se autoriza exactamente
`/etc/self-hosted-ci/dispatcher-app.json`, el mismo archivo root-only que se pasó
a `configure-garm-jit.sh`.

Preparar los artefactos unsigned. El output debe ser una ruta nueva y el
assembler no firma ni hace llamadas de red:

```bash
nonce=<32-hex-nonce>
prepared="/var/lib/self-hosted-ci/canary-assembly/${nonce}"

sudo python3 /path/to/self-hosted-ci/scripts/host/assemble-jit-canary-runtime.py prepare \
  --output-directory "${prepared}" \
  --authorization-template /root/self-hosted-ci-canary/authorization-template.json \
  --dispatcher-app-config /etc/self-hosted-ci/dispatcher-app.json \
  --default-branch main \
  --reviewer-public-key /etc/self-hosted-ci/boundary-reviewer-public-key.pem \
  --allocation-signer-private-key /etc/self-hosted-ci/secrets/allocation-ed25519.pem \
  --garm-health-file /etc/self-hosted-ci/garm/health-state.json \
  --broker-config-file /etc/self-hosted-ci/garm/allocation-broker.json \
  --live-job-verifier /usr/local/libexec/self-hosted-ci/github-live-job-verifier.py \
  --network-policy /usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh \
  --bootstrap-install-receipt /var/lib/self-hosted-ci/bootstrap/bootstrap-install-receipt-v1.json \
  --reviewer-public-key-runtime-path /etc/self-hosted-ci/boundary-reviewer-public-key.pem \
  --allocation-signer-runtime-path /etc/self-hosted-ci/secrets/allocation-ed25519.pem \
  --garm-health-runtime-path /etc/self-hosted-ci/garm/health-state.json \
  --broker-config-runtime-path /etc/self-hosted-ci/garm/allocation-broker.json \
  --live-job-verifier-runtime-path /usr/local/libexec/self-hosted-ci/github-live-job-verifier.py \
  --network-policy-runtime-path /usr/local/lib/self-hosted-ci/apply-runner-network-policy.sh \
  --bootstrap-install-receipt-runtime-path /var/lib/self-hosted-ci/bootstrap/bootstrap-install-receipt-v1.json
```

El manifest de preparación debe decir
`prepared-awaiting-external-signature`, `github_contacted: false` y registrar el
path, SHA-256 y byte count de `/etc/self-hosted-ci/dispatcher-app.json`.
`runtime-config.json` debe apuntar a esa misma ruta; no existe un
`dispatcher-runtime.json` intermedio.

Firmar fuera del checkout el unsigned exacto que produjo el assembler:

```bash
sudo python3 /path/to/self-hosted-ci/scripts/host/sign-jit-canary-authorization.py \
  --input "${prepared}/authorization-unsigned.json" \
  --output "/var/lib/self-hosted-ci/canary-assembly/${nonce}.signed.json" \
  --reviewer-private-key </absolute/path/outside/repo/reviewer-private-key.pem>
```

Finalmente verificar la firma externa y crear el tar y su manifest. Ambos
outputs deben ser nuevos:

```bash
sudo python3 /path/to/self-hosted-ci/scripts/host/assemble-jit-canary-runtime.py bundle \
  --prepared-directory "${prepared}" \
  --signed-authorization "/var/lib/self-hosted-ci/canary-assembly/${nonce}.signed.json" \
  --reviewer-public-key /etc/self-hosted-ci/boundary-reviewer-public-key.pem \
  --output-tar /root/self-hosted-ci-canary-output/canary-runtime-bundle.tar \
  --output-manifest /root/self-hosted-ci-canary-output/canary-runtime-bundle.manifest.json

sudo python3 - <<'PY'
import json, pathlib
p=pathlib.Path('/root/self-hosted-ci-canary-output/canary-runtime-bundle.manifest.json')
v=json.loads(p.read_text())
print('ExpectedBundleSha256='+v['bundle']['sha256'])
print('ExpectedBundleBytes='+str(v['bundle']['bytes']))
print('ExpectedReviewerFingerprint='+v['reviewer_fingerprint'])
PY
```

El bundle USTAR resultante tiene owner `0:0`, modo `0600` y exactamente:

```text
canary/authorization.json
canary/runtime-config.json
```

`authorization.json` es el documento firmado anterior. `runtime-config.json`
usa las rutas root-only ya instaladas de reviewer key, dispatcher App,
live-job verifier, policy, bootstrap receipt, health de GARM, broker y clave de
allocation; no copia ninguna clave privada dentro del tar. Calcular SHA-256,
tamaño y nonce desde el manifest, incorporar ambos archivos a
`C:\ProgramData\self-hosted-ci\package\artifacts\canary` mediante el updater
pinneado, y ejecutar desde PowerShell elevada:

```powershell
& "C:\ProgramData\self-hosted-ci\package\scripts\host\run-wsl-jit-canary-matrix.ps1" `
  -ExpectedServiceAccountSid '<SID-from-local-inventory>' `
  -ExpectedBundleSha256 '<64-hex-sha256>' `
  -ExpectedBundleBytes <exact-positive-bytes> `
  -ExpectedReviewerFingerprint '<64-hex-spki-sha256>' `
  -ExpectedCanaryNonce '<32-hex-nonce>' `
  -Apply `
  -AcknowledgeCanaryGitHubContact `
  -AcknowledgeTransientRunnerRegistration `
  -AcknowledgeDistroRestart `
  -AcknowledgeOneTimePasswordRotation
```

El wrapper transmite el mismo bundle por stdin, sin drvfs. Para `reboot`
acepta únicamente el checkpoint durable, termina la distro exacta, reinserta
el mismo bundle/nonce y reanuda. El éxito exige los seis scale sets efímeros ya
eliminados, cero runners/registrations/instancias, servicios canary detenidos y
cuarentena activa.

Los proofs quedan bajo
`/var/lib/self-hosted-ci/canary/<nonce>/proofs/`. Ensamblarlos en el orden
canónico; `--output` debe ser nuevo:

```bash
sudo /usr/local/lib/self-hosted-ci/build-wsl-jit-lifecycle-evidence.py \
  --authorization /etc/self-hosted-ci/canary-authorization.json \
  --reviewer-public-key /etc/self-hosted-ci/boundary-reviewer-public-key.pem \
  --pinned-fingerprint <64-hex-spki-sha256> \
  --proof /var/lib/self-hosted-ci/canary/<nonce>/proofs/success.json \
  --proof /var/lib/self-hosted-ci/canary/<nonce>/proofs/failure.json \
  --proof /var/lib/self-hosted-ci/canary/<nonce>/proofs/cancel.json \
  --proof /var/lib/self-hosted-ci/canary/<nonce>/proofs/timeout.json \
  --proof /var/lib/self-hosted-ci/canary/<nonce>/proofs/force-cancel.json \
  --proof /var/lib/self-hosted-ci/canary/<nonce>/proofs/reboot.json \
  --output /var/lib/self-hosted-ci/canary/<nonce>/runner-lifecycle-proof-set-v1.json
```

Incorporar esa salida exacta como `runner_lifecycle_proof_set`, regenerar,
medir, firmar y volver a instalar el live contract final con la ceremonia de
`stage-wsl-jit-live-contract.py`, `collect-wsl-jit-measurements.py`,
`sign-wsl-jit-boundary.py` e `install-wsl-jit-live-contract.ps1` documentada
arriba. Recién ese boundary final habilita la activación de producción.

La activación no recibe identidad de scale set porque debe empezar y terminar
con inventario cero; las allocations posteriores son dinámicas y pertenecen al
broker. Revisar el plan y aplicar:

```bash
sudo /usr/local/lib/self-hosted-ci/activate-garm-jit.sh --plan
sudo /usr/local/lib/self-hosted-ci/activate-garm-jit.sh --apply \
  --incus-project ci-jit --garm-cli-home /run/self-hosted-ci/garm-cli \
  --acknowledge-external-github-mutation \
  --acknowledge-local-ci-activation
```

## Sandbox y GitHub App

La registry es hosted-by-default. El sandbox es el único candidato inicial;
su entrada local debe incluir `local-with-github-fallback`, autoridad exacta,
installation ID, runner group restringido cuando corresponda y execution trust.
La App debe tener permisos mínimos y nunca compartir identidad con el reviewer.

El broker usa además una App lane de sólo lectura para probar el job live antes
del primer step. Instalá fuera del repo la clave privada y el archivo
`/etc/self-hosted-ci/github-live-job-verifier.json`, ambos `root:root 0600`. El
JSON contiene únicamente `app_id`, `installation_id` y `private_key_file`; la
App debe estar instalada con selección del repositorio exacto y `Actions:
read`. El verificador no acepta endpoint, token, clave ni IDs por argumentos o
variables de ambiente, y vuelve a restringir cada installation token al
`repository_id` firmado.

El runtime JIT debe hacer polling outbound, pedir JIT para repo y SHA exactos,
crear un container efímero no privilegiado, aceptar exactamente un job y
destruirlo en success, failure, cancel, timeout, force-cancel y reboot. Debe
registrar cleanup durable y cero runners, tokens o containers huérfanos.

El provisioning deja instalados GARM, el provider Incus, la frontera TLS y el
runtime de red sin crear credenciales GitHub ni un scale set. La etapa inerte de
configuración posterior instala la entidad y las credenciales exactas en GARM,
pero exige cero scale sets y tampoco registra runners. Cada escenario canary y
cada allocation de producción crea su propio scale set efímero y lo elimina al
terminar. Hasta que la GitHub App, la imagen y el lifecycle real pasen el smoke live,
ningún repositorio debe autorizar el backend local.

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

La desactivación operativa corta primero la admisión del outbound worker y del
broker; después recupera, deshabilita, drena y elimina todas las allocations
efímeras antes de retirar GARM o la policy de red. No recibe IDs manuales:

```bash
sudo /usr/local/lib/self-hosted-ci/deactivate-garm-jit.sh --plan
sudo /usr/local/lib/self-hosted-ci/deactivate-garm-jit.sh --apply \
  --incus-project ci-jit --garm-cli-home /run/self-hosted-ci/garm-cli \
  --acknowledge-external-github-mutation \
  --acknowledge-local-ci-deactivation
```

Si el login renovable falla durante esta desactivación, el script conserva
GARM, el sentinel y los servicios protectores, y aplica inmediatamente la
política de cuarentena del bridge. No retira la frontera de red sin haber
eliminado todos los scale sets efímeros y probado cero runners/instancias.

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

## Actualizar el live contract desde Windows

### Bootstrap semántico inerte

El primer provisioning ya no depende de un `runner-boundary-v2` fabricado a
mano. Antes de instalar runtime se recolectan dos observaciones independientes:

- `collect-windows-wsl-semantic-contract.ps1` observa, desde una PowerShell
  elevada, la cuenta local exacta, pertenencia efectiva a Administrators,
  registro WSL bajo el SID de servicio, BasePath y ACL. Es read-only respecto
  del host y guarda evidencia privada protegida para SYSTEM/Administrators.
- `collect-wsl-jit-semantic-observations.sh` corre dentro de la distro de
  servicio y observa configuración WSL, mounts/interop, superficies de
  credenciales, identidades Linux, pins de software, Incus, red y estado inerte
  de GARM. No acepta flags ni overrides y nunca emite un `pass` proporcionado
  por el operador.

`build-wsl-jit-bootstrap-manifest.py` genera un manifiesto JCS que fija cada
source, target, mode, tamaño y SHA-256 público que el provisioner podrá instalar
o ejecutar. `build-wsl-jit-bootstrap.py` deriva el contrato únicamente si ambas
observaciones y ese manifiesto satisfacen sus verificadores semánticos. Luego
`sign-wsl-jit-bootstrap.py` usa una clave Ed25519 externa y un dominio de firma
exclusivo de bootstrap. El contrato resultante sólo autoriza
`provision-wsl-jit-contract` en modo `inert-only`: no autoriza GitHub,
activation, `runtime-ready` ni registro de runners.

Flujo reproducible, manteniendo observaciones y claves fuera del repositorio:

```powershell
& "C:\ProgramData\self-hosted-ci\package\scripts\host\collect-wsl-jit-bootstrap-evidence.ps1" `
  -ExpectedServiceAccountSid "<SID-EXACTO>" -Apply `
  -AcknowledgeBootstrapEvidenceCollection `
  -AcknowledgeOneTimePasswordRotation
```

El comando devuelve las dos rutas privadas content-addressed. Copialas al host
revisor y generá un challenge nuevo de 128 bits para vincular esa autorización:

```bash
nonce="$(openssl rand -hex 16)"
python3 scripts/host/build-wsl-jit-bootstrap-manifest.py \
  --output /private/bootstrap-public-manifest-v1.json
python3 scripts/host/build-wsl-jit-bootstrap.py \
  --windows-observation /private/windows-observation.json \
  --wsl-observation /private/wsl-observation.json \
  --public-manifest /private/bootstrap-public-manifest-v1.json \
  --nonce "$nonce" \
  --output /private/bootstrap-boundary-v1.unsigned.json
python3 scripts/host/sign-wsl-jit-bootstrap.py \
  --input /private/bootstrap-boundary-v1.unsigned.json \
  --output /private/bootstrap-boundary-v1.signed.json \
  --reviewer-private-key /private/reviewer-private-key.pem
```

Conservá `nonce` sólo hasta aplicar el bootstrap. El provisioner exige ese
challenge exacto, observaciones recientes y una autorización con TTL de diez
minutos; otro nonce o bytes públicos distintos invalidan el contrato. El mismo
bundle puede reintentarse de forma idempotente durante ese TTL: este challenge
vincula la ceremonia, pero no es un token persistente de un solo uso.

El provisioner acepta los dos contratos de forma mutuamente exclusiva:

```bash
sudo scripts/host/provision-wsl-jit-contract.sh --apply \
  --bootstrap-evidence /private/bootstrap-boundary-v1.signed.json \
  --windows-observation /private/windows-observation.json \
  --wsl-observation /private/wsl-observation.json \
  --public-manifest /private/bootstrap-public-manifest-v1.json \
  --reviewer-public-key /private/reviewer-public-key.pem \
  --reviewer-key-fingerprint <sha256-spki-del-reviewer> \
  --expected-bootstrap-nonce "$nonce" \
  --acknowledge-host-mutation \
  --acknowledge-dedicated-boundary
```

En bootstrap, los servicios de boundary, red, proxy, broker, outbound worker y
GARM terminan disabled; `ACTIVATION_APPROVED` y
`outbound-worker.runtime-ready` deben estar ausentes antes de empezar. El
`runner-boundary-v2` final sigue siendo obligatorio después de los canaries de
lifecycle y reboot; un bootstrap firmado no puede sustituirlo.

La instalación sobre la distro que pertenece a la cuenta de servicio se hace
con `scripts/host/install-wsl-jit-live-contract.ps1`. El script es plan-only por
defecto y usa una tarea one-shot `Password`/`Limited`; no activa GARM, no
configura GitHub, no crea `outbound-worker.runtime-ready` y no registra runners.

El flujo tiene dos operaciones separadas. Primero, el paquete contiene
`artifacts/live-contract/unsigned-live-contract-source.tar`: un tar POSIX
determinista, root-owned, con un único árbol `contract/`, el template en
`contract/runner-boundary-template-v2.json` y todos sus archivos públicos de
medición. Construí ese input sin metadata dependiente de la máquina:

```bash
python3 scripts/host/build-wsl-jit-live-contract-tar.py source \
  --contract-dir /path/to/unsigned-contract-source \
  --output artifacts/live-contract/unsigned-live-contract-source.tar
```

La recolección ocurre adentro de la distro de servicio y no
provisiona nada. Corré primero el mismo comando sin `-Apply`: el JSON del plan
informa `input_sha256` e `input_bytes`. Copiá ambos valores literalmente al
apply como expectativa externa del archivo que Windows va a abrir:

```powershell
& "C:\ProgramData\self-hosted-ci\package\scripts\host\install-wsl-jit-live-contract.ps1" `
  -ExpectedServiceAccountSid "<SID-exacto-de-selfhosted-ci-svc>" `
  -CollectUnsigned `
  -Apply `
  -ExpectedInputSha256 "<sha256-del-source-tar>" `
  -ExpectedInputBytes <bytes-del-source-tar> `
  -AcknowledgeUnsignedCollection `
  -AcknowledgeOneTimePasswordRotation
```

El JSON final informa un path content-addressed bajo
`C:\ProgramData\self-hosted-ci\unsigned-live-contract`. Copiá exactamente ese
tar fuera de Windows, firmá `runner-boundary-measured-v2.json` con
`scripts/host/sign-wsl-jit-boundary.py`, agregá sólo la clave pública y su
fingerprint, y construí el bundle final con el helper. El helper verifica la
firma y que el fingerprint corresponda al SPKI Ed25519 antes de escribir el
tar; no acepta ni lee una clave privada:

```bash
python3 scripts/host/sign-wsl-jit-boundary.py \
  --input /path/to/contract/runner-boundary-measured-v2.json \
  --output /path/to/runner-boundary-v2.json \
  --reviewer-private-key /absolute/path/outside/repo/reviewer-private-key.pem

python3 scripts/host/build-wsl-jit-live-contract-tar.py signed \
  --unsigned-tar /path/to/unsigned-live-contract-<sha256>.tar \
  --signed-boundary /path/to/runner-boundary-v2.json \
  --reviewer-public-key /path/to/reviewer-public-key.pem \
  --reviewer-key-fingerprint <sha256-spki-del-reviewer> \
  --output artifacts/live-contract/live-contract-bundle.tar
```

La clave privada del reviewer permanece fuera de Windows y fuera del
repositorio. El flujo detallado de stage, medición, firma y verificación está
en [`wsl-jit-runner-mvp.md`](wsl-jit-runner-mvp.md).

Con el bundle firmado ya copiado al paquete, corré otra vez el plan para leer
su SHA-256 y tamaño. El fingerprint esperado es el SHA-256 lowercase del SPKI
DER de la clave pública del reviewer, calculado fuera de Windows; el
fingerprint incluido en el bundle no es una raíz de confianza. Después, desde
una PowerShell elevada:

```powershell
& "C:\ProgramData\self-hosted-ci\package\scripts\host\install-wsl-jit-live-contract.ps1" `
  -ExpectedServiceAccountSid "<SID-exacto-de-selfhosted-ci-svc>" `
  -Apply `
  -ExpectedInputSha256 "<sha256-del-bundle-firmado>" `
  -ExpectedInputBytes <bytes-del-bundle-firmado> `
  -ExpectedReviewerFingerprint "<sha256-spki-del-reviewer>" `
  -AcknowledgeLiveContractMutation `
  -AcknowledgeOneTimePasswordRotation
```

El éxito exige que la tarea, la credencial almacenada y el staging hayan sido
eliminados; además re-mide el contrato dentro de la distro y exige igualdad con
el contenido firmado antes de provisionar. Un fallo conserva sólo diagnósticos
redactados y deja el sistema sin activation/runtime-ready nuevos.
