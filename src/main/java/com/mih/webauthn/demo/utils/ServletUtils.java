package com.mih.webauthn.demo.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mih.webauthn.demo.domain.vo.RegisterParams;
import io.github.webauthn.dto.AssertionFinishRequest;
import io.github.webauthn.dto.RegistrationStartRequest;
import io.github.webauthn.dto.RegistrationStartResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Component
public class ServletUtils {

    private static final Logger log = LoggerFactory.getLogger(ServletUtils.class);

    @Autowired
    private ObjectMapper mapper ;

    public <T> T parseRequest(ServletRequest request, Class<T> clasz) throws IOException {
        return mapper.readValue(request.getReader(), clasz);
    }

    public RegistrationStartRequest parseRegisterParams(RegisterParams registerParams) {
        RegistrationStartRequest body = new RegistrationStartRequest();
        body.setUsername(registerParams.getUsername());
        body.setRecoveryToken(registerParams.getRecoveryToken());
        body.setRegistrationAddToken(registerParams.getRegistrationAddToken());
        return body;
    }

    public void writeBadRequestToResponse(ServletResponse response, RegistrationStartResponse body) throws IOException {
        writeToResponse(HttpServletResponse.SC_BAD_REQUEST, response, mapper.writeValueAsString(body));
    }

    public void writeBadRequestToResponse(ServletResponse response, Map<String, String> body) throws IOException {
        writeToResponse(HttpServletResponse.SC_BAD_REQUEST, response, mapper.writeValueAsString(body));
    }

    public void writeToResponse(ServletResponse response, String body) throws IOException {
        writeToResponse(HttpServletResponse.SC_OK, response, body);
    }

    public void writeToResponse(ServletResponse response, Map<Object, Object> body) throws IOException {
        writeToResponse(HttpServletResponse.SC_OK, response, mapper.writeValueAsString(body));
    }

    private void writeToResponse(int status, ServletResponse response, String body) throws IOException {
        log.debug("writeToResponse - status: {}, body: {}", status, body);
        HttpServletResponse res = (HttpServletResponse) response;
        res.setCharacterEncoding("utf-8");
        res.setStatus(status);
        res.getWriter().write(body);
        res.getWriter().flush();
    }
}
