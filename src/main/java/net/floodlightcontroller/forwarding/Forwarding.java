/**
 *    Copyright 2011, Big Switch Networks, Inc.
 *    Originally created by David Erickson, Stanford University
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 **/

package net.floodlightcontroller.forwarding;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import extra.HTTPRequests;
import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.debugcounter.IDebugCounterService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.*;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.FlowModUtils;
import net.floodlightcontroller.util.OFDPAUtils;
import net.floodlightcontroller.util.OFPortMode;
import net.floodlightcontroller.util.OFPortModeTuple;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFGroupType;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFGroup;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.TableId;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;
import org.python.antlr.ast.Str;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Forwarding extends ForwardingBase implements IFloodlightModule, IOFSwitchListener {
	protected static Logger log = LoggerFactory.getLogger(Forwarding.class);

	private final ConcurrentHashMap<String, Long> connectionRequests = new ConcurrentHashMap<>();
	private static final long TIMEOUT_MS = 5000;

	private String generateConnectionKey(String macSrc, String macDst) {
		return macSrc + "->" + macDst;
	}

	@Override
	public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		// We found a routing decision (i.e. Firewall is enabled... it's the only thing that makes RoutingDecisions)
		// Filtrar paquetes no relevantes (no IPv4 o no ICMP)

		if (decision != null) {
			if (log.isTraceEnabled()) {
				log.trace("Forwarding decision={} was made for PacketIn={}", decision.getRoutingAction().toString(), pi);
			}

			switch(decision.getRoutingAction()) {
			case NONE:
				// don't do anything
				return Command.CONTINUE;
			case FORWARD_OR_FLOOD:
			case FORWARD:
				doForwardFlow(sw, pi, cntx, false);
				return Command.CONTINUE;
			case MULTICAST:
				// treat as broadcast
				doFlood(sw, pi, cntx);
				return Command.CONTINUE;
			case DROP:
				doDropFlow(sw, pi, decision, cntx);
				return Command.CONTINUE;
			default:
				log.error("Unexpected decision made for this packet-in={}", pi, decision.getRoutingAction());
				return Command.CONTINUE;
			}
		} else { // No routing decision was found. Forward to destination or flood if bcast or mcast.
			if (log.isTraceEnabled()) {
				log.trace("No decision was made for PacketIn={}, forwarding", pi);
			}
			if (eth.isBroadcast() || eth.isMulticast()) {
				doFlood(sw, pi, cntx);
			} else {
				doForwardFlow(sw, pi, cntx, false);
			}
		}

		return Command.CONTINUE;
	}

	protected void doDropFlow(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		Match m = createMatchFromPacket(sw, inPort, cntx);

		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd(); // this will be a drop-flow; a flow that will not output to any ports
		List<OFAction> actions = new ArrayList<OFAction>(); // set no action to drop
		U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);
		log.info("Droppingggg");
		fmb.setCookie(cookie)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setMatch(m)
		.setPriority(FLOWMOD_DEFAULT_PRIORITY);
		
		FlowModUtils.setActions(fmb, actions, sw);

		try {
			if (log.isDebugEnabled()) {
				log.debug("write drop flow-mod sw={} match={} flow-mod={}",
						new Object[] { sw, m, fmb.build() });
			}
			boolean dampened = messageDamper.write(sw, fmb.build());
			log.debug("OFMessage dampened: {}", dampened);
		} catch (IOException e) {
			log.error("Failure writing drop flow mod", e);
		}
	}

	protected void doForwardFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, boolean requestFlowRemovedNotifn) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		IDevice dstDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_DST_DEVICE);
		DatapathId source = sw.getId();

		Integer idleTimeout=600;
		Integer hardTimeout=0;
		Integer priority=100;
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

// Obtener direcciones MAC de origen y destino
		String macSrc = eth.getSourceMACAddress().toString();
		String macDst = eth.getDestinationMACAddress().toString();

		// Generar clave para la conexión
		String connectionKey = generateConnectionKey(macSrc, macDst);
		String connectionKeyInversed = generateConnectionKey(macDst, macSrc);

		// Verificar si la conexión ya fue procesada
		Long timestamp = connectionRequests.get(connectionKeyInversed);
		long currentTime = System.currentTimeMillis();

		if (timestamp != null && (currentTime - timestamp) < TIMEOUT_MS) {
			log.info("Solicitud de conexión ya procesada para {}", connectionKey);
			return;
		}


		if (dstDevice != null) {
			IDevice srcDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE);


			if (srcDevice == null) {
				log.error("No device entry found for source device. Is the device manager running? If so, report bug.");
				return;
			}
			log.info("----- Solicitud PACKET-IN entre "+srcDevice.getMACAddressString()+" y "+dstDevice.getMACAddressString()+" -----");

			if (FLOOD_ALL_ARP_PACKETS && 
					IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD).getEtherType() 
					== EthType.ARP) {
				log.debug("ARP flows disabled in Forwarding. Flooding ARP packet");
				doFlood(sw, pi, cntx);
				return;
			}

			/* Validate that the source and destination are not on the same switch port */
			boolean on_same_if = false;
			for (SwitchPort dstDap : dstDevice.getAttachmentPoints()) {
				if (sw.getId().equals(dstDap.getSwitchDPID()) && inPort.equals(dstDap.getPort())) {
					on_same_if = true;
				}
				break;
			}

			if (on_same_if) {
				log.info("Both source and destination are on the same switch/port {}/{}. Action = NOP", sw.toString(), inPort);
				return;
			}
	
			SwitchPort[] dstDaps = dstDevice.getAttachmentPoints();
			SwitchPort dstDap = null;

			/*
			 * Search for the true attachment point. The true AP is
			 * not an endpoint of a link. It is a switch port w/o an
			 * associated link. Note this does not necessarily hold
			 * true for devices that 'live' between OpenFlow islands.
			 *
			 * TODO Account for the case where a device is actually
			 * attached between islands (possibly on a non-OF switch
			 * in between two OpenFlow switches).
			 */
			for (SwitchPort ap : dstDaps) {
				if (topologyService.isEdge(ap.getSwitchDPID(), ap.getPort())) {
					dstDap = ap;
					break;
				}
			}

			/*
			 * This should only happen (perhaps) when the controller is
			 * actively learning a new topology and hasn't discovered
			 * all links yet, or a switch was in standalone mode and the
			 * packet in question was captured in flight on the dst point
			 * of a link.
			 */
			if (dstDap == null) {
				log.warn("Could not locate edge attachment point for device {}. Flooding packet");
				doFlood(sw, pi, cntx);
				return;
			}
			
			/* It's possible that we learned packed destination while it was in flight */
			if (!topologyService.isEdge(source, inPort)) {	
				log.debug("Packet destination is known, but packet was not received on an edge port (rx on {}/{}). Flooding packet", source, inPort);
				doFlood(sw, pi, cntx);
				return; 
			}

			IDevice srcDeviceAux=dstDevice;
			IDevice dstDeviceAux=srcDevice;

			log.info("----- Solicitud PACKET-IN entre "+srcDevice.getMACAddressString()+" y "+dstDevice.getMACAddressString()+" -----");
			log.info("----- El motivo es una comunicación entre "+srcDeviceAux.getMACAddressString()+" y "+dstDeviceAux.getMACAddressString()+" -----");

			Boolean hostOrigenInvitado=false;
			Boolean hostDestinoInvitado=false;

			Map<String,Object> dispositivoOrigenResponse=(Map<String,Object>) HTTPRequests.obtenerDispositivo(srcDeviceAux.getMACAddressString());
			String status=(String) dispositivoOrigenResponse.get("status");
			log.info("----- STATUS src: "+status+" -----");
			if(status.equals("error")){
				hostOrigenInvitado=true;
				HTTPRequests.registrarDispositivoInvitado(srcDeviceAux.getMACAddressString());
				log.info("----- Se registró un nuevo dispositivo origen invitado: "+srcDeviceAux.getMACAddressString()+" -----");
			}else{
				Map<String,Object>dispositivo=(Map<String,Object>)dispositivoOrigenResponse.get("content");
				Object usuario=dispositivo.get("usuario");
				if(usuario==null){
					hostOrigenInvitado=true;
					log.info("----- El dispositivo origen está registrado como invitado: "+srcDeviceAux.getMACAddressString()+" -----");
				}else if(dispositivo.get("autenticado").equals(0)){
					hostOrigenInvitado=true;
					log.info("----- El dispositivo origen no ha sido autenticado por su usuario: "+srcDeviceAux.getMACAddressString()+" -----");
				}else {
					Map<String,Object>enSesionResponse=(Map<String, Object>) HTTPRequests.verificarUsuarioEnSesion((String) ((Map<String,Object>)usuario).get("username"));
					if(enSesionResponse.get("status").equals("error")){
						log.info("----- El usuario que registró al dispositivo origen no está en sesión: "+srcDeviceAux.getMACAddressString()+" -----");
						hostOrigenInvitado=true;
					}else {
						log.info("----- El dispositivo origen pasará a una segunda validación: "+srcDeviceAux.getMACAddressString()+" -----");
					}
				}
			}

			Map<String,Object> dispositivoDestinoResponse=(Map<String,Object>)HTTPRequests.obtenerDispositivo(dstDeviceAux.getMACAddressString());
			status=(String) dispositivoDestinoResponse.get("status");
			log.info("----- STATUS dst: "+status+" -----");
			if(status.equals("error")){
				hostDestinoInvitado=true;
				HTTPRequests.registrarDispositivoInvitado(dstDeviceAux.getMACAddressString());
				log.info("----- Se registró un nuevo dispositivo destino invitado: "+dstDeviceAux.getMACAddressString()+" -----");
			}else{
				Map<String,Object>dispositivo=(Map<String,Object>)dispositivoDestinoResponse.get("content");
				Object usuario=dispositivo.get("usuario");
				Integer autenticado = ((Double) dispositivo.get("autenticado")).intValue();
				if(usuario==null){
					log.info("----- El dispositivo destino está registrado como invitado: "+dstDeviceAux.getMACAddressString()+" -----");
					hostDestinoInvitado=true;
				}else if(autenticado==0||autenticado==1){
					log.info("----- El dispositivo destino no ha sido autenticado por su usuario o este desea que sea accesible como invitado: "+dstDevice.getMACAddressString()+" -----");
					hostDestinoInvitado=true;
				}else {
					Map<String,Object>enSesionResponse=(Map<String, Object>) HTTPRequests.verificarUsuarioEnSesion((String) ((Map<String,Object>)usuario).get("username"));
					if(enSesionResponse.get("status").equals("error")){
						hostOrigenInvitado=true;
						log.info("----- El usuario que registró al dispositivo destino no está en sesión: "+dstDeviceAux.getMACAddressString()+" -----");
					}else {
						log.info("----- El dispositivo destino pasará a una segunda validación: "+dstDeviceAux.getMACAddressString()+" -----");
					}
				}
			}
			log.info("----- Host origen invitado: "+hostOrigenInvitado+" -----");
			log.info("----- Host destino invitado: "+hostDestinoInvitado+" -----");
			Integer idVlan=null;
			Integer puerto=0;
			String nombreServicio=null;


			Integer puertoDestino=null;

			// Verificar si el paquete es IPv4
			if (eth.getEtherType() == EthType.IPv4) {
				IPv4 ipv4 = (IPv4) eth.getPayload();

				// Verificar si el protocolo es TCP
				if (ipv4.getProtocol() == IpProtocol.TCP) {
					TCP tcp = (TCP) ipv4.getPayload();

					// Obtener el puerto destino
					puertoDestino = tcp.getDestinationPort().getPort();

					log.info("Puerto TCP destino: {}", puertoDestino);
				}
			}

			if(hostOrigenInvitado){
				if(hostDestinoInvitado){
					idVlan=1;
				}else {
					idVlan=null;
				}
			}else {
				if(hostDestinoInvitado){
					idVlan=1;
				}else {
					Map<String,Object>vinculoResponse=(Map<String, Object>) HTTPRequests.obtenerVinculoTerminales(srcDeviceAux.getMACAddressString(),dstDeviceAux.getMACAddressString());
					Map<String,Object>content=(Map<String,Object>) vinculoResponse.get("content");
					Map<String,Object>servicio=(Map<String,Object>) content.get("servicio");
					if(servicio!=null){
						idVlan=((Double) servicio.get("id")).intValue();
						nombreServicio=(String) servicio.get("nombre");
						List<Integer>listaPuertosServicio=(List<Integer>)servicio.get("puertos");
						if(listaPuertosServicio.isEmpty()){
							puerto=0;
						}else {
							if(listaPuertosServicio.contains(puertoDestino)){
								puerto=puertoDestino;
							}else {
								puerto=null;
							}
						}
					}
				}
			}

			if(idVlan==null){
				log.error("----- No se obtuvo un valor de ID VLAN válido. No se puede establecer una conexión con el destino -----");
				// Agregar la conexión al registro
				connectionRequests.put(connectionKey, currentTime);
				return;
			}else {
				if(puerto==null){
					log.error("----- El puerto destino no es permitido. No se puede establecer una conexión con el destino -----");
					// Agregar la conexión al registro
					connectionRequests.put(connectionKey, currentTime);
					return;
				}
			}
			log.info("----- Servicio en comun: "+(nombreServicio==null?"Invitado":nombreServicio)+" con ID VLAN: "+idVlan+" y puerto "+(puerto==0?"0 (todos los puertos)":puerto)+" -----");

			log.info("----- Se está iniciando la creación de una conexión entre "+srcDeviceAux.getMACAddressString()+" y "+dstDeviceAux.getMACAddressString()+" -----");



			Route route = routingEngineService.getRoute(dstDap.getSwitchDPID(),
					dstDap.getPort(),
					source,
					inPort, U64.of(0)); //cookie = 0, i.e., default route

			Match m = crearMatchInicialPorPaquete(sw, inPort, cntx,puerto);

			U64 cookie = AppCookie.makeCookie(FORWARDING_APP_ID, 0);

			if (route != null) {
				log.info("pushRoute inPort={} route={} " +
						"destination={}:{}",
						new Object[] { inPort, route,
						dstDap.getSwitchDPID(),
						dstDap.getPort()});


				log.debug("Cretaing flow rules on the route, match rule: {}", m);
				insertarRutas(route, m, pi, sw.getId(), cookie,
						cntx, requestFlowRemovedNotifn,
						OFFlowModCommand.ADD,
						eth.getSourceMACAddress(),
						eth.getDestinationMACAddress(),
						idleTimeout,
						hardTimeout,
						idVlan,
						priority,
						puerto);
			} else {
				/* Route traverses no links --> src/dst devices on same switch */
				log.info("Could not compute route. Devices should be on same switch src={} and dst={}", srcDevice, dstDevice);
				Route r = new Route(srcDevice.getAttachmentPoints()[0].getSwitchDPID(), dstDevice.getAttachmentPoints()[0].getSwitchDPID());
				List<NodePortTuple> path = new ArrayList<NodePortTuple>(2);
				path.add(new NodePortTuple(srcDevice.getAttachmentPoints()[0].getSwitchDPID(),
						srcDevice.getAttachmentPoints()[0].getPort()));
				path.add(new NodePortTuple(dstDevice.getAttachmentPoints()[0].getSwitchDPID(),
						dstDevice.getAttachmentPoints()[0].getPort()));
				r.setPath(path);
				insertarRutas(r, m, pi, sw.getId(), cookie,
						cntx, requestFlowRemovedNotifn,
						OFFlowModCommand.ADD,
						eth.getSourceMACAddress(),
						eth.getDestinationMACAddress(),
						idleTimeout,
						hardTimeout,
						idVlan,
						priority,
						puerto);
			}
			HTTPRequests.registrarNuevaConexion(srcDeviceAux.getMACAddressString(), dstDeviceAux.getMACAddressString(),idVlan,puerto,idleTimeout);
			System.out.println("----- Se estableció una conexión entre "+srcDeviceAux.getMACAddressString()+" y "+dstDeviceAux.getMACAddressString()+" -----");

		} else {
			log.debug("Destination unknown. Flooding packet");
			doFlood(sw, pi, cntx);
		}
	}

	/**
	 * Instead of using the Firewall's routing decision Match, which might be as general
	 * as "in_port" and inadvertently Match packets erroneously, construct a more
	 * specific Match based on the deserialized OFPacketIn's payload, which has been 
	 * placed in the FloodlightContext already by the Controller.
	 * 
	 * @param sw, the switch on which the packet was received
	 * @param inPort, the ingress switch port on which the packet was received
	 * @param cntx, the current context which contains the deserialized packet
	 * @return a composed Match object based on the provided information
	 */
	protected Match createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {
		// The packet in match will only contain the port number.
		// We need to add in specifics for the hosts we're routing between.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		VlanVid vlan = VlanVid.ofVlan(eth.getVlanID());
		MacAddress srcMac = eth.getSourceMACAddress();
		MacAddress dstMac = eth.getDestinationMACAddress();

		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.IN_PORT, inPort);

		if (FLOWMOD_DEFAULT_MATCH_MAC) {
			mb.setExact(MatchField.ETH_SRC, srcMac)
			.setExact(MatchField.ETH_DST, dstMac);
		}

		if (FLOWMOD_DEFAULT_MATCH_VLAN) {
			if (!vlan.equals(VlanVid.ZERO)) {
				mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
			}
		}

		// TODO Detect switch type and match to create hardware-implemented flow
		if (eth.getEtherType() == EthType.IPv4) { /* shallow check for equality is okay for EthType */
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4Address srcIp = ip.getSourceAddress();
			IPv4Address dstIp = ip.getDestinationAddress();

			if (FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
						.setExact(MatchField.IPV4_SRC, srcIp)
						.setExact(MatchField.IPV4_DST, dstIp);
			}

			if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
				/*
				 * Take care of the ethertype if not included earlier,
				 * since it's a prerequisite for transport ports.
				 */
				if (!FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
					mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				}

				if (ip.getProtocol().equals(IpProtocol.TCP)) {
					TCP tcp = (TCP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
							.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
							.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
				} else if (ip.getProtocol().equals(IpProtocol.UDP)) {
					UDP udp = (UDP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
							.setExact(MatchField.UDP_SRC, udp.getSourcePort())
							.setExact(MatchField.UDP_DST, udp.getDestinationPort());
				}
			}
		} else if (eth.getEtherType() == EthType.ARP) { /* shallow check for equality is okay for EthType */
			mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
		} else if (eth.getEtherType() == EthType.IPv6) {
			IPv6 ip = (IPv6) eth.getPayload();
			IPv6Address srcIp = ip.getSourceAddress();
			IPv6Address dstIp = ip.getDestinationAddress();

			if (FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv6)
						.setExact(MatchField.IPV6_SRC, srcIp)
						.setExact(MatchField.IPV6_DST, dstIp);
			}

			if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
				/*
				 * Take care of the ethertype if not included earlier,
				 * since it's a prerequisite for transport ports.
				 */
				if (!FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
					mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
				}

				if (ip.getNextHeader().equals(IpProtocol.TCP)) {
					TCP tcp = (TCP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
							.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
							.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
				} else if (ip.getNextHeader().equals(IpProtocol.UDP)) {
					UDP udp = (UDP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
							.setExact(MatchField.UDP_SRC, udp.getSourcePort())
							.setExact(MatchField.UDP_DST, udp.getDestinationPort());
				}
			}
		}
		return mb.build();
	}

	protected Match crearMatchInicialPorPaquete(IOFSwitch sw, OFPort inPort, FloodlightContext cntx,Integer puerto) {
		// The packet in match will only contain the port number.
		// We need to add in specifics for the hosts we're routing between.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

		Match.Builder mb = sw.getOFFactory().buildMatch();
		return mb.build();
	}

	/**
	 * Creates a OFPacketOut with the OFPacketIn data that is flooded on all ports unless
	 * the port is blocked, in which case the packet will be dropped.
	 * @param sw The switch that receives the OFPacketIn
	 * @param pi The OFPacketIn that came to the switch
	 * @param cntx The FloodlightContext associated with this OFPacketIn
	 */
	protected void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		// Set Action to flood
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		List<OFAction> actions = new ArrayList<OFAction>();
		Set<OFPort> broadcastPorts = this.topologyService.getSwitchBroadcastPorts(sw.getId());

		if (broadcastPorts == null) {
			log.debug("BroadcastPorts returned null. Assuming single switch w/no links.");
			/* Must be a single-switch w/no links */
			broadcastPorts = Collections.singleton(OFPort.FLOOD);
		}
		
		for (OFPort p : broadcastPorts) {
			if (p.equals(inPort)) continue;
			actions.add(sw.getOFFactory().actions().output(p, Integer.MAX_VALUE));
		}
		pob.setActions(actions);
		// log.info("actions {}",actions);
		// set buffer-id, in-port and packet-data based on packet-in
		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);
		pob.setData(pi.getData());

		try {
			if (log.isTraceEnabled()) {
				log.trace("Writing flood PacketOut switch={} packet-in={} packet-out={}",
						new Object[] {sw, pi, pob.build()});
			}
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			log.error("Failure writing PacketOut switch={} packet-in={} packet-out={}",
					new Object[] {sw, pi, pob.build()}, e);
		}

		return;
	}

	// IFloodlightModule methods

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// We don't export any services
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService>
	getServiceImpls() {
		// We don't have any services
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(IRoutingService.class);
		l.add(ITopologyService.class);
		l.add(IDebugCounterService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		super.init();
		this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		this.deviceManagerService = context.getServiceImpl(IDeviceService.class);
		this.routingEngineService = context.getServiceImpl(IRoutingService.class);
		this.topologyService = context.getServiceImpl(ITopologyService.class);
		this.debugCounterService = context.getServiceImpl(IDebugCounterService.class);
		this.switchService = context.getServiceImpl(IOFSwitchService.class);

		Map<String, String> configParameters = context.getConfigParams(this);
		String tmp = configParameters.get("hard-timeout");
		if (tmp != null) {
			FLOWMOD_DEFAULT_HARD_TIMEOUT = Integer.parseInt(tmp);
			log.info("Default hard timeout set to {}.", FLOWMOD_DEFAULT_HARD_TIMEOUT);
		} else {
			log.info("Default hard timeout not configured. Using {}.", FLOWMOD_DEFAULT_HARD_TIMEOUT);
		}
		tmp = configParameters.get("idle-timeout");
		if (tmp != null) {
			FLOWMOD_DEFAULT_IDLE_TIMEOUT = Integer.parseInt(tmp);
			log.info("Default idle timeout set to {}.", FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		} else {
			log.info("Default idle timeout not configured. Using {}.", FLOWMOD_DEFAULT_IDLE_TIMEOUT);
		}
		tmp = configParameters.get("priority");
		if (tmp != null) {
			FLOWMOD_DEFAULT_PRIORITY = 35777;
			log.info("Default priority set to {}.", FLOWMOD_DEFAULT_PRIORITY);
		} else {
			log.info("Default priority not configured. Using {}.", FLOWMOD_DEFAULT_PRIORITY);
		}
		tmp = configParameters.get("set-send-flow-rem-flag");
		if (tmp != null) {
			FLOWMOD_DEFAULT_SET_SEND_FLOW_REM_FLAG = Boolean.parseBoolean(tmp);
			log.info("Default flags will be set to SEND_FLOW_REM.");
		} else {
			log.info("Default flags will be empty.");
		}
		tmp = configParameters.get("match");
		if (tmp != null) {
			tmp = tmp.toLowerCase();
			if (!tmp.contains("vlan") && !tmp.contains("mac") && !tmp.contains("ip") && !tmp.contains("port")) {
				/* leave the default configuration -- blank or invalid 'match' value */
			} else {
				FLOWMOD_DEFAULT_MATCH_VLAN = tmp.contains("vlan") ? true : false;
				FLOWMOD_DEFAULT_MATCH_MAC = tmp.contains("mac") ? true : false;
				FLOWMOD_DEFAULT_MATCH_IP_ADDR = tmp.contains("ip") ? true : false;
				FLOWMOD_DEFAULT_MATCH_TRANSPORT = tmp.contains("port") ? true : false;

			}
		}
		log.info("Default flow matches set to: VLAN=" + FLOWMOD_DEFAULT_MATCH_VLAN
				+ ", MAC=" + FLOWMOD_DEFAULT_MATCH_MAC
				+ ", IP=" + FLOWMOD_DEFAULT_MATCH_IP_ADDR
				+ ", TPPT=" + FLOWMOD_DEFAULT_MATCH_TRANSPORT);
		
		tmp = configParameters.get("flood-arp");
		if (tmp != null) {
			tmp = tmp.toLowerCase();
			if (!tmp.contains("yes") && !tmp.contains("yep") && !tmp.contains("true") && !tmp.contains("ja") && !tmp.contains("stimmt")) {
				FLOOD_ALL_ARP_PACKETS = false;
				log.info("Not flooding ARP packets. ARP flows will be inserted for known destinations");
			} else {
				FLOOD_ALL_ARP_PACKETS = true;
				log.info("Flooding all ARP packets. No ARP flows will be inserted");
			}
		}
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		super.startUp();
		switchService.addOFSwitchListener(this);
	}

	@Override
	public void switchAdded(DatapathId switchId) {
	}

	@Override
	public void switchRemoved(DatapathId switchId) {		
	}

	@Override
	public void switchActivated(DatapathId switchId) {
		IOFSwitch sw = switchService.getSwitch(switchId);
		if (sw == null) {
			log.warn("Switch {} was activated but had no switch object in the switch service. Perhaps it quickly disconnected", switchId);
			return;
		}
		if (OFDPAUtils.isOFDPASwitch(sw)) {
			sw.write(sw.getOFFactory().buildFlowDelete()
					.setTableId(TableId.ALL)
					.build()
					);
			sw.write(sw.getOFFactory().buildGroupDelete()
					.setGroup(OFGroup.ANY)
					.setGroupType(OFGroupType.ALL)
					.build()
					);
			sw.write(sw.getOFFactory().buildGroupDelete()
					.setGroup(OFGroup.ANY)
					.setGroupType(OFGroupType.INDIRECT)
					.build()
					);
			sw.write(sw.getOFFactory().buildBarrierRequest().build());
			
			List<OFPortModeTuple> portModes = new ArrayList<OFPortModeTuple>();
			for (OFPortDesc p : sw.getPorts()) {
				portModes.add(OFPortModeTuple.of(p.getPortNo(), OFPortMode.ACCESS));
			}
			if (log.isWarnEnabled()) {
				log.warn("For OF-DPA switch {}, initializing VLAN {} on ports {}", new Object[] { switchId, VlanVid.ZERO, portModes});
			}
			OFDPAUtils.addLearningSwitchPrereqs(sw, VlanVid.ZERO, portModes);
		}
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {		
	}

	@Override
	public void switchChanged(DatapathId switchId) {
	}

	protected void installFloodRule(IOFSwitch sw) {
		// Match all ARP packets
		Match match = sw.getOFFactory().buildMatch()
				.setExact(MatchField.ETH_TYPE, EthType.ARP)
				.build();

		// Create the flood action
		OFAction floodAction = sw.getOFFactory().actions().output(OFPort.FLOOD, Integer.MAX_VALUE);

		// Build the flow modification message
		OFFlowMod flowMod = sw.getOFFactory().buildFlowAdd()
				.setMatch(match) // Match criteria (ARP packets)
				.setActions(Collections.singletonList(floodAction)) // Flood action
				.setIdleTimeout(600) // Rule expires after 600 seconds of inactivity
				.setHardTimeout(0) // No hard timeout (doesn't expire automatically)
				.setPriority(200) // Higher priority than default rules
				.setBufferId(OFBufferId.NO_BUFFER) // No buffering
				.build();

		// Write the flow modification to the switch
		try {
			sw.write(flowMod);
			log.info("Regla de Flooding ARP instalada en el switch {}", sw.getId());
		} catch (Exception e) {
			log.error("Error al instalar regla de Flooding ARP instalada en el switch {}", sw.getId(), e);
		}
	}

}
