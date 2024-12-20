package extra;

import com.google.common.reflect.TypeToken;
import com.google.gson.Gson;
import org.restlet.Client;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.Method;
import org.restlet.data.Protocol;

import java.lang.reflect.Type;
import java.util.HashMap;


public class HTTPRequests {

    private static final Gson gson = new Gson();
    private static final Client client = new Client(Protocol.HTTP);

    public static Object registrarNuevaConexion(String macOrigen, String macDestino, Integer idVlan, Integer puerto, Integer timeout) {
        String url = "http://localhost:8081/sdn/auth/registrarNuevaConexion?macOrigen=" + macOrigen +
                "&macDestino=" + macDestino + "&idVlan=" + idVlan + "&puerto=" + puerto + "&timeout=" + timeout;
        return sendGetRequest(url);
    }

    public static Object registrarDispositivoInvitado(String mac) {
        String url = "http://localhost:8081/sdn/auth/registrarDispositivoInvitado?mac=" + mac;
        return sendGetRequest(url);
    }

    public static Object obtenerDispositivo(String mac) {
        String url = "http://localhost:8081/sdn/auth/obtenerDispositivo?mac=" + mac;
        return sendGetRequest(url);
    }

    public static Object obtenerVinculoTerminales(String macOrigen, String macDestino) {
        String url = "http://localhost:8081/sdn/auth/obtenerVinculoTerminales?macOrigen=" + macOrigen + "&macDestino=" + macDestino;
        return sendGetRequest(url);
    }

    public static Object obtenerNivelAcceso(String mac) {
        String url = "http://localhost:8081/sdn/auth/obtenerNivelAcceso?mac=" + mac;
        return sendGetRequest(url);
    }

    public static Object verificarUsuarioEnSesion(String username) {
        String url = "http://localhost:8081/sdn/auth/verificarUsuarioEnSesion?username=" + username;
        return sendGetRequest(url);
    }

    private static Object sendGetRequest(String url) {
        try {
            Request request = new Request(Method.POST, url);
            Response response = client.handle(request);

            if (response.getStatus().isSuccess()) {
                String jsonResponse = response.getEntity().getText();
                Type type = new TypeToken<HashMap<String, Object>>() {}.getType();
                return gson.fromJson(jsonResponse, type);
            } else {
                System.err.println("Error en la solicitud: " + response.getStatus());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
