import networkx as nx
import matplotlib.pyplot as plt
from typing import Dict, Any

class ReconVisualizer:
    @staticmethod
    def generate_network_map(nodes: Dict[str, Any]) -> nx.Graph:
        """Create network graph from recon data"""
        G = nx.Graph()
        
        # Add nodes with attributes
        for node_id, data in nodes.items():
            G.add_node(node_id, **data)
            
        # Add relationships (customize based on your data)
        if 'dns' in nodes:
            for record_type, values in nodes['dns'].items():
                for value in values:
                    G.add_edge(nodes['target'], value, relationship=record_type)
                    
        return G

    @staticmethod
    def draw_graph(G: nx.Graph, output_file: str = 'network.png'):
        """Visualize the network graph"""
        plt.figure(figsize=(12, 12))
        pos = nx.spring_layout(G, k=0.5)
        
        nx.draw_networkx_nodes(G, pos, node_size=700)
        nx.draw_networkx_edges(G, pos, width=1.5)
        nx.draw_networkx_labels(G, pos, font_size=10)
        
        edge_labels = nx.get_edge_attributes(G, 'relationship')
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
        
        plt.axis('off')
        plt.savefig(output_file, format='PNG', dpi=300)
        plt.close()