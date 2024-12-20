package net.floodlightcontroller.forwarding;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.TableId;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class DeleteFlowRulesResource extends ServerResource {
    protected static Logger log = LoggerFactory.getLogger(DeleteFlowRulesResource.class);
    @Post("json")
    public Map<String, String> deleteRulesByMac(String macAddress) {
        Map<String, String> response = new HashMap<>();
        try {
            MacAddress mac = MacAddress.of(macAddress);
            IOFSwitchService switchService =
                    (IOFSwitchService) getContext().getAttributes().get(IOFSwitchService.class.getCanonicalName());

            for (IOFSwitch sw : switchService.getAllSwitchMap().values()) {
                // Crear un Match para las reglas que coincidan con MAC origen
                Match.Builder matchSrc = sw.getOFFactory().buildMatch();
                matchSrc.setExact(MatchField.ETH_SRC, mac);

                // Crear un FlowDelete para eliminar reglas coincidentes con ETH_SRC
                OFFlowMod.Builder flowDeleteSrc = sw.getOFFactory().buildFlowDelete();
                flowDeleteSrc.setMatch(matchSrc.build())
                        .setTableId(TableId.ALL) // Asegúrate de buscar en todas las tablas
                        .setPriority(0);         // Prioridad más baja para eliminar cualquier regla coincidente

                // Enviar la solicitud al switch
                try {
                    sw.write(flowDeleteSrc.build());
                    log.info("Reglas asociadas a MAC origen {} eliminadas en el switch {}", macAddress, sw.getId());
                } catch (Exception e) {
                    log.error("Error al eliminar reglas por MAC origen en el switch {}: {}", sw.getId(), e.getMessage());
                }

                // Crear un Match para las reglas que coincidan con MAC destino
                Match.Builder matchDst = sw.getOFFactory().buildMatch();
                matchDst.setExact(MatchField.ETH_DST, mac);

                // Crear un FlowDelete para eliminar reglas coincidentes con ETH_DST
                OFFlowMod.Builder flowDeleteDst = sw.getOFFactory().buildFlowDelete();
                flowDeleteDst.setMatch(matchDst.build())
                        .setTableId(TableId.ALL) // Asegúrate de buscar en todas las tablas
                        .setPriority(0);         // Prioridad más baja para eliminar cualquier regla coincidente

                // Enviar la solicitud al switch
                try {
                    sw.write(flowDeleteDst.build());
                    log.info("Reglas asociadas a MAC destino {} eliminadas en el switch {}", macAddress, sw.getId());
                } catch (Exception e) {
                    log.error("Error al eliminar reglas por MAC destino en el switch {}: {}", sw.getId(), e.getMessage());
                }; // Llama a tu método aquí
            }

            response.put("status", "success");
            response.put("message", "Reglas de flujo eliminadas para MAC: " + macAddress);
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Error al eliminar reglas de flujo: " + e.getMessage());
        }
        return response;
    }

    private void borrarReglasPorMac(IOFSwitch sw, MacAddress macAddress) {
        Logger log = LoggerFactory.getLogger(this.getClass());


    }
}
