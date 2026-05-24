# Sentinel — Caso de uso: aprobación de préstamos

> **El agente de IA en la nube aprueba el crédito sin ver jamás el SSN, el número de cuenta
> ni el nombre del solicitante — y cada decisión queda probada línea por línea con
> `raw_sensitive_bytes_to_cloud: 0`.**

---

## 1. El problema del banco

Hoy un banco recibe la solicitud de Juan: recibos de nómina, estados de cuenta, declaración
de impuestos y su SSN. Un analista humano lee todo y decide si lo aprueban. Es **lento**
(días), **caro** (un analista cuesta ~$80k/año y revisa ~20 casos al día) y **no escala**.

El banco quiere que un agente de IA en la nube haga ese trabajo: leer los documentos, extraer
los números, detectar inconsistencias y redactar una recomendación. Eso requiere el
razonamiento de un modelo frontier, no un regex local.

**Pero esos documentos están llenos de datos regulados** (SSN, números de cuenta, saldos).
Legalmente el banco **no puede** mandarlos crudos a una API de IA. Está atrapado entre dos
malas opciones: quedarse con el proceso humano lento, o asumir el riesgo legal.

Sentinel es la tercera opción: el razonamiento del agente cloud **+** la prueba auditable de
que el dato crudo nunca salió.

---

## 2. El objetivo de negocio

El banco no compra "privacidad". Compra **velocidad, costo y escala**:

- **Más rápido** — aprobar en minutos en vez de días → no pierde al cliente contra el competidor.
- **Más barato** — automatizar lo que hoy hacen ejércitos de analistas.
- **A escala** — procesar 100× volumen sin contratar 100× personas.
- **Consistente** — dos analistas humanos deciden distinto sobre el mismo caso; la IA no.

La privacidad no es el objetivo: es el **muro** que hoy le impide alcanzar ese objetivo.
Sentinel derriba el muro.

---

## 3. La clave: identificadores vs. variables de decisión

Una decisión de crédito es, en el fondo, **ratios y consistencia** — no la identidad. Los
documentos de Juan contienen dos tipos de datos casi disjuntos:

| Tipo | Ejemplos | ¿El agente lo necesita? | Qué hace Sentinel |
|---|---|---|---|
| **A — Identificadores** | Nombre, SSN, nº de cuenta, dirección, fecha de nacimiento | **No** para decidir. Solo necesita saber *que existe y es válido*. | Enmascara local → nunca sube crudo |
| **B — Variables de decisión** | Ingreso $8,000/mes, deuda $2,000/mes, antigüedad 4 años, saldo $15,000, sobregiros 0 | **Sí** — es lo que mueve la decisión | Razona sobre el valor (anónimo) o solo el resultado |

El DTI (deuda/ingreso = 25 %) es lo que aprueba o rechaza, **no** los dígitos del SSN.

---

## 4. El flujo, paso a paso

```
1. REDACT  (local, en tu DGX Spark)
   Documento crudo:
     "Juan Perez, SSN 412-55-7890, cuenta 0033219, gana $8,000/mes, debe $2,000/mes"
                              |
                              v   el modelo local enmascara identificadores
   Documento que sube a la nube:
     "[PERSON_1], SSN [SSN_1], cuenta [ACCT_1], gana $8,000/mes, debe $2,000/mes"

2. REASON  (agente cloud, sobre el documento enmascarado)
   - Calcula DTI = 2000 / 8000 = 25%  -> saludable
   - Ve 0 sobregiros, 4 anios de empleo  -> perfil estable
   - Pero no confia ciegamente: el ingreso declarado, ?es real? el SSN, ?existe?

3. VERIFY  (callback al modelo local — solo si/no)
   El agente pregunta a tu Spark a traves del allowlist:
     - "?SSN [SSN_1] es valido y no esta en lista de fraude?"            -> SI
     - "?los depositos reales en [ACCT_1] confirman los $8,000?"         -> SI
     - "?la cuenta pertenece al solicitante?"                            -> SI
   Recibe veredictos. Nunca recibe el SSN ni el numero de cuenta.

4. DECIDE + audit
   "Recomiendo APROBAR: DTI 25%, ingreso verificado, identidad verificada,
    sin senales de fraude."
   + audit-log.json : raw_sensitive_bytes_to_cloud = 0
```

---

## 5. ¿Qué datos sí le sirven al agente?

Tres cosas, y **ninguna** es un identificador crudo:

1. **Valores agregados / derivados** que el humano también usaría: ingreso, deuda, ratios,
   antigüedad, tendencia del saldo.
2. **Veredictos booleanos** que solo el lado local puede producir: "SSN válido", "ingreso
   coincide con depósitos reales", "sin fraude".
3. **Contexto e inconsistencias**: "declara $8k pero los depósitos suman $5k" — exactamente
   lo que quieres que marque.

---

## 6. El dial: modo estándar vs. estricto

¿El ingreso de $8,000 no es también sensible? Sí. Por eso hay una palanca:

- **Modo estándar** — enmascaras solo identificadores (SSN, cuenta, nombre); los montos pasan.
  El agente razona con números reales pero **anónimos**. Sin identidad, no es PII
  reidentificable.
- **Modo estricto** — ni los montos suben. El DTI se calcula **local** y al agente solo le
  llega el resultado categórico ("DTI: saludable") + los veredictos. El agente toma la
  decisión de crédito habiendo visto, literalmente, una lista de "sí / sí / sí / DTI saludable".
  **Razona sobre datos que nunca poseyó.**

---

## 7. Por qué importa

| Sin Sentinel | Con Sentinel |
|---|---|
| Proceso humano lento y caro, **o** | Decisión en segundos |
| Riesgo legal de mandar PII a la nube | `raw_sensitive_bytes_to_cloud: 0`, probado |
| "Confía en nosotros" | Audit-log línea por línea |

Sentinel no vende privacidad. Vende el **objetivo de negocio desbloqueado** —velocidad, costo,
escala— con la privacidad resuelta como condición de entrada, y la prueba para demostrarlo.

---

*Construido sobre Google Managed Agents: `AGENTS.md` · `code_execution` · network allowlist +
header transform (el callback de verificación) · multi-turn · file artifacts. Datos de prueba
sintéticos — sin datos personales reales.*
