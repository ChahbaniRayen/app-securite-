# SonarQube

Conteneur démarré par `orchestrator/setup_sonarqube.sh` (port 9000).

Première connexion : http://<host>:9000 (admin — définir le mot de passe à la
première connexion), puis créer un token d'analyse :
Compte > Mes jetons > Générer (type "Analysis Token") et exporter :
    export SONAR_TOKEN=<jeton>
