FROM quay.io/keycloak/keycloak:26.6.2@sha256:f9ba7b2af90db8dc749a57ca9aedca51e840cb9224441ab546a968da941da900

COPY stack.kotlin/keycloak-onboarding-listener/build/libs/keycloak-onboarding-listener-1.0-SNAPSHOT-all.jar /opt/keycloak/providers/keycloak-onboarding-listener.jar

RUN /opt/keycloak/bin/kc.sh build
