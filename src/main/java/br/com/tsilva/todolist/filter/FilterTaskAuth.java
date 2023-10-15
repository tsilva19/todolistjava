package br.com.tsilva.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.tsilva.todolist.user.IUserRepository;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    // Valida  se  o usuário  esta autenticado ou não, se Estiver  segue o fluxo para o controller por meio do filterChain.doFilter(request, response);
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        var servletPath = request.getServletPath();

        if (servletPath.startsWith("/tasks/")){
            var authorization =   request.getHeader("Authorization");

            var authEncoded = authorization.substring("Basic".length()).trim();

            byte[]  authDecode =   Base64.getDecoder().decode(authEncoded);
            var authString = new String(authDecode);

            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            System.out.println("Authorization");
            System.out.println(authString);

            var user = this.userRepository.findByUsername(username);
            if (user == null){
                response.sendError(401);
            } else {
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVerify.verified){
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }
            }

        }else {
            filterChain.doFilter(request, response);
        }


    }




}
