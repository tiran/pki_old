project(pki-cms)

find_file(JSS_JAR
    NAMES
        jss4.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(LDAPJDK_JAR
    NAMES
        ldapjdk.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(COMMONS_CODEC_JAR
    NAMES
        commons-codec.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_HTTPCLIENT_JAR
    NAMES
        commons-httpclient.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_IO_JAR
    NAMES
        commons-io.jar
    PATHS
        /usr/share/java
)

find_file(COMMONS_LANG_JAR
    NAMES
        commons-lang.jar
    PATHS
        /usr/share/java
)

find_file(VELOCITY_JAR
    NAMES
        velocity.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XALAN_JAR
    NAMES
        xalan-j2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(XERCES_JAR
    NAMES
        xerces-j2.jar
    PATHS
        ${JAVA_LIB_INSTALL_DIR}
        /usr/share/java
)

find_file(RESTEASY_JAXRS_JAR
    NAMES
        resteasy-jaxrs.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(RESTEASY_ATOM_PROVIDER_JAR
    NAMES
        resteasy-atom-provider.jar
    PATHS
        ${RESTEASY_LIB}
)

find_file(HTTPCLIENT_JAR
    NAMES
        httpclient.jar
    PATHS
        /usr/share/java/httpcomponents
)

find_file(HTTPCORE_JAR
    NAMES
        httpcore.jar
    PATHS
        /usr/share/java/httpcomponents
)

# build pki-cms
javac(pki-cms-classes
    SOURCES
        *.java
    CLASSPATH
        ${SLF4J_API_JAR}
        ${COMMONS_CODEC_JAR} ${COMMONS_IO_JAR} ${COMMONS_LANG_JAR} ${COMMONS_HTTPCLIENT_JAR}
        ${HTTPCLIENT_JAR} ${HTTPCORE_JAR}
        ${XALAN_JAR} ${XERCES_JAR}
        ${JSS_JAR} ${SYMKEY_JAR}
        ${LDAPJDK_JAR}
        ${SERVLET_JAR} ${TOMCAT_CATALINA_JAR} ${TOMCAT_UTIL_JAR}
        ${TOMCATJSS_JAR} ${VELOCITY_JAR}
        ${JAXRS_API_JAR} ${RESTEASY_JAXRS_JAR} ${RESTEASY_ATOM_PROVIDER_JAR}
        ${PKI_NSUTIL_JAR} ${PKI_CMSUTIL_JAR} ${PKI_CERTSRV_JAR} ${PKI_TOMCAT_JAR}
    OUTPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-nsutil-jar pki-cmsutil-jar pki-certsrv-jar pki-tomcat-jar
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/pki-cms.mf
    ${CMAKE_CURRENT_BINARY_DIR}/pki-cms.mf
)

jar(pki-cms-jar
    CREATE
        ${CMAKE_BINARY_DIR}/dist/pki-cms.jar
    OPTIONS
        m
    PARAMS
        ${CMAKE_CURRENT_BINARY_DIR}/pki-cms.mf
    INPUT_DIR
        ${CMAKE_CURRENT_BINARY_DIR}/classes
    DEPENDS
        pki-cms-classes
)

install(
    FILES
        ${CMAKE_BINARY_DIR}/dist/pki-cms.jar
    DESTINATION
        ${JAVA_JAR_INSTALL_DIR}/pki
)

set(PKI_CMS_JAR ${CMAKE_BINARY_DIR}/dist/pki-cms.jar CACHE INTERNAL "pki-cms jar file")
