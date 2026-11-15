# BYTE Security
## Sistema de detección de ransomware basado en comportamiento y recuperación de archivos

Prototipo académico que combina aprendizaje automático y reglas de comportamiento para identificar patrones compatibles con ransomware, registrar sesiones sospechosas y recuperar archivos desde copias locales de respaldo.

---

## 1. Descripción general

BYTE Security es un sistema experimental de detección y recuperación ante patrones de actividad asociados con ransomware.

El proyecto analiza eventos de actividad sobre archivos, extrae características de comportamiento y utiliza un modelo de Machine Learning junto con reglas adicionales para clasificar las sesiones.

El sistema incluye:

- Generación de eventos benignos y patrones simulados de ransomware.
- Extracción de características de comportamiento.
- Clasificación mediante Random Forest.
- Detección complementaria mediante reglas conductuales.
- API REST desarrollada con FastAPI.
- Almacenamiento de sesiones y amenazas mediante SQLite.
- Copias locales de archivos para permitir su recuperación.
- Dashboard web desarrollado con React y Vite.
- Módulos experimentales relacionados con staging y protección cloud.

**Alcance:** es un prototipo académico. Las pruebas realizadas utilizan eventos y archivos de laboratorio. No debe considerarse un antivirus ni una solución de protección empresarial en producción.

---

## 2. Arquitectura del sistema

El flujo principal implementado y probado es:

```text
        SIMULADOR
  Eventos de actividad sobre archivos
              |
              v
       ARCHIVO NDJSON
              |
              v
       REPLAY TO BACKEND
       Envío de eventos HTTP
              |
              v
       FASTAPI BACKEND
              |
              v
      EXTRACCIÓN DE FEATURES
              |
              v
       MOTOR DE DETECCIÓN
       +------------------+
       | Random Forest    |
       | Regla conductual |
       +------------------+
              |
              v
       CLASIFICACIÓN
       Benigno / Ransomware
              |
        +-----+------+
        |            |
        v            v
    SQLite       Amenaza
                     |
                     v
              VERSION STORE
                     |
                     v
              RECUPERACIÓN
                     |
                     v
              ARCHIVOS RESTAURADOS

              REACT DASHBOARD
         Consulta información del backend


Componentes
Componente    Responsabilidad
Simulator    Generar actividad de archivos para escenarios de prueba.
Feature Extraction    Extraer características de comportamiento.
ML Model    Entrenar y evaluar modelos de clasificación.
Backend    Recibir eventos, ejecutar detección y almacenar resultados.
Recovery    Gestionar la restauración desde copias locales.
Cloud Protection    Contiene módulos experimentales de staging y cuarentena.
Dashboard    Presentar sesiones, amenazas y resultados de recuperación.
Driver / Monitor Service    Componentes adicionales del repositorio, cuyo funcionamiento independiente no forma parte de las pruebas documentadas aquí.


3. Tecnologías utilizadas
Backend y Machine Learning
- Python 3.11
- FastAPI
- Uvicorn
- SQLAlchemy
- SQLite
- NumPy
- Pandas
- Scikit-learn
- Joblib
Frontend
- React 18
- Vite 5
- JavaScript
Datos y pruebas
- Archivos NDJSON
- Dataset sintético de comportamiento
- Simulación controlada en directorios de prueba

4. Estructura del proyecto

ransomware-detection/
|
|-- backend/
|   |-- main.py
|   |-- config.py
|   |-- database.py
|   |-- schemas.py
|   |-- services/
|
|-- candidate_v3/
|   |-- models/
|       |-- best_model.joblib
|       |-- feature_columns.json
|
|-- cloud-protection/
|-- dashboard/
|   |-- src/
|   |-- public/
|   |-- package.json
|
|-- docs/
|-- driver/
|   |-- minifilter/
|
|-- feature-extraction/
|   |-- extractor.py
|
|-- ml-model/
|   |-- models/
|   |-- train.py
|   |-- train_behavioral.py
|   |-- train_robust.py
|
|-- monitor-service/
|-- plots/
|-- recovery/
|-- simulator/
|   |-- diverse_dataset_generator.py
|   |-- ransomware_pattern_generator.py
|   |-- benign_generator.py
|   |-- replay_to_backend.py
|   |-- restore_sandbox.py
|
|-- README.md
|-- .gitignore

Nota: las bases de datos, los registros, los entornos virtuales y los archivos generados durante las pruebas se mantienen localmente y no forman parte del repositorio.

5. Instalación y configuración en Windows
Requisitos
- Windows 10 u 11.
- Python 3.11.
- Node.js y npm.
- PowerShell.
5.1 Crear y activar el entorno virtual
Desde la carpeta raíz del proyecto:
python -m venv .venv
.\.venv\Scripts\Activate.ps1


5.2 Instalar dependencias
python -m pip install --upgrade pip

pip install -r .\simulator\requirements-backend.txt

pip install numpy pandas scikit-learn joblib


El archivo requirements-backend.txt contiene las dependencias principales del backend. Las dependencias adicionales permiten trabajar con el modelo y el entrenamiento.
5.3 Instalar dependencias del dashboard
En otra terminal de PowerShell:
cd .\dashboard
npm install



6. Entrenamiento del modelo
El proyecto incluye varios scripts de entrenamiento. La versión utilizada para generar el modelo candidato v3 es:

ml-model/train_behavioral.py
6.1 Generar el dataset sintético
Desde la raíz del proyecto:
python .\simulator\diverse_dataset_generator.py `
  --out .\feature-extraction\output\features_diverse_v3.csv `
  --n 250 `
  --seed 42


Este comando genera escenarios benignos y patrones simulados de ransomware.

Con --n 250 se generan 250 registros por clase, para un total de 500 registros.
6.2 Entrenar el modelo
python .\ml-model\train_behavioral.py `
  --features .\feature-extraction\output\features_diverse_v3.csv `
  --out-dir .\candidate_v3


Los archivos del modelo se guardan en:
candidate_v3/
    models/
        best_model.joblib
        feature_columns.json


6.3 Modelo utilizado
El backend utiliza el clasificador Random Forest cargado desde candidate_v3.

El vector de entrada utiliza las características definidas en feature_columns.json.

La detección también incorpora una regla conductual complementaria. Por tanto, el resultado final no depende exclusivamente de la predicción del modelo.

Importante: los resultados de evaluación obtenidos con datos sintéticos no representan la precisión esperada frente a ransomware real. Se necesitan datasets externos y pruebas controladas adicionales para evaluar la generalización.

7. Motor de detección
El motor está implementado en:

backend/services/detection.py

La detección combina dos mecanismos:
7.1 Machine Learning
Random Forest analiza las características extraídas de cada sesión y calcula una probabilidad de pertenencia a la clase ransomware.
7.2 Regla conductual
Se activa una detección adicional cuando se cumplen simultáneamente estas condiciones:
- Al menos 3 archivos diferentes presentan cambios de extensión.
- Se registran al menos 3 eventos WRITE.
- Se registran al menos 3 eventos RENAME.
- La duración de la sesión es de 10 segundos o menos.
Cuando la regla conductual detecta un patrón y el modelo no lo detecta, el riesgo mostrado se eleva como mínimo a 85%.

Esta regla permite detectar algunos ataques pequeños que el modelo por sí solo podría clasificar como benignos.

Limitación: una operación legítima que renombre muchos archivos rápidamente podría activar la regla. Es necesario ampliar las pruebas con escenarios benignos difíciles y ajustar los umbrales.

8. Ejecución del sistema
Se recomienda ejecutar el backend y el dashboard en terminales separadas.
8.1 Iniciar el backend
Desde la raíz del proyecto, con el entorno virtual activado:
$env:MODEL_PATH = (Resolve-Path .\candidate_v3\models\best_model.joblib).Path

$env:FEAT_COL_PATH = (Resolve-Path .\candidate_v3\models\feature_columns.json).Path

cd .\backend

uvicorn main:app --reload --port 8000


El backend estará disponible en:
- API: http://127.0.0.1:8000
- Documentación Swagger: http://127.0.0.1:8000/docs
No cierres esta terminal mientras estés utilizando el sistema.
8.2 Iniciar el dashboard
En una segunda terminal:
cd .\dashboard
npm run dev


Vite mostrará la dirección local disponible. En el entorno de desarrollo utilizado para las pruebas, el dashboard se abrió en:

http://localhost:5175

Si el puerto está ocupado, Vite puede seleccionar otro. Utiliza la dirección que aparezca en la terminal.

9. Simulación y envío de eventos
El simulador permite generar actividad controlada sobre archivos dentro de un directorio de pruebas.
9.1 Generar un patrón de ransomware
Ejemplo para un escenario de tres archivos:
python .\simulator\ransomware_pattern_generator.py `
  --sandbox .\simulator\integration-test\candidate-test-3files `
  --log .\simulator\integration-test\logs\candidate-test-3files.ndjson `
  --session-id candidate-test-3files-20261114 `
  --max-files 3


El simulador genera eventos y guarda copias de respaldo para las pruebas de recuperación.
9.2 Enviar los eventos al backend
Con el backend en ejecución:
python .\simulator\replay_to_backend.py `
  --log .\simulator\integration-test\logs\candidate-test-3files.ndjson `
  --url http://127.0.0.1:8000


El backend recibe los eventos, procesa la sesión y almacena el resultado.
9.3 Consultar los resultados
Se pueden consultar las sesiones y amenazas desde:
- GET /api/sessions
- GET /api/threats
- GET /api/stats
- GET /api/status
También se pueden visualizar desde el dashboard.

10. Recuperación de archivos
El sistema utiliza un almacenamiento local de versiones para conservar copias de los archivos procesados por el simulador.

La recuperación se solicita mediante:
POST /api/recovery/restore/{session_id}


Ejemplo con PowerShell:
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/api/recovery/restore/candidate-test-3files-20261114" |
  ConvertTo-Json -Depth 5


El servicio verifica los respaldos y restaura los archivos originales en el directorio de prueba.

La recuperación implementada y validada corresponde al almacenamiento local del prototipo. No representa una restauración desde un proveedor cloud ni desde Windows Volume Shadow Copy Service (VSS).

11. API Reference
La API está implementada en backend/main.py.
Método    Endpoint    Descripción
GET    /api/status    Estado del sistema y del modelo.
GET    /api/stats    Estadísticas generales para el dashboard.
POST    /api/sessions/ingest    Recibir eventos y ejecutar la detección.
GET    /api/sessions    Consultar sesiones procesadas.
GET    /api/threats    Consultar amenazas detectadas.
POST    /api/recovery/restore/{session_id}    Restaurar archivos de una sesión.
GET    /api/recovery/actions    Consultar operaciones de recuperación.
GET    /api/cloud/quarantine    Consultar archivos en cuarentena.
GET    /api/cloud/staging    Consultar archivos en staging.
POST    /api/cloud/staging/add    Simular la entrada de un archivo a staging.

La documentación interactiva está disponible en:

http://127.0.0.1:8000/docs

12. Pruebas realizadas
Se realizaron pruebas controladas utilizando el backend, el modelo candidato v3 y el simulador.
Escenario    Eventos    Resultado    Riesgo
Patrón ransomware de 5 archivos    10    Ransomware    85%
Patrón ransomware de 3 archivos    6    Ransomware    85%
Escenario benigno    16    Benigno    0.2%

Pruebas de recuperación
Sesión    Archivos restaurados    Archivos fallidos
Ataque de 3 archivos    3    0
Ataque de 5 archivos    5    0

También se verificó que los archivos originales recuperados estuvieran presentes en sus directorios de prueba y que los archivos con extensión .locked correspondientes fueran retirados.

Estos resultados demuestran el funcionamiento en los escenarios específicos probados. No constituyen una evaluación exhaustiva de detección en entornos reales.

13. Seguridad y limitaciones
- Las pruebas deben ejecutarse únicamente en directorios de laboratorio.
- El simulador no debe utilizarse sobre documentos personales o carpetas de producción.
- La detección se basa en características de comportamiento y reglas; puede producir falsos positivos o falsos negativos.
- El modelo fue entrenado con datos sintéticos.
- El sistema no ha sido validado frente a familias reales de ransomware.
- La recuperación depende de que existan copias locales válidas.
- Los módulos de cloud protection, driver y monitorización deben evaluarse por separado antes de considerarlos mecanismos de protección operativos.
- No se debe interpretar el dashboard como un sistema de protección de endpoints en producción.

14. Propósito académico
BYTE Security fue desarrollado como un proyecto académico para explorar la aplicación de Machine Learning, análisis de comportamiento, APIs, visualización de datos y recuperación de archivos en un escenario de detección de ransomware.

El objetivo es demostrar la integración de estos componentes en un prototipo funcional y controlado, así como identificar sus limitaciones y oportunidades de mejora.

<div align="center">
<strong>BYTE Security</strong>


<sub>Prototipo académico de detección conductual y recuperación local de archivos.</sub>

</div>

