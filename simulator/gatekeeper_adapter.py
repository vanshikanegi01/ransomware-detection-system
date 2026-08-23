"""
Integration adapter connecting SafeRansomwareSimulator to Gatekeeper.
"""
from typing import List, Tuple
from pathlib import Path

from gatekeeper.gatekeeper import GatekeeperAgent
from gatekeeper.models import ScreeningResult
from simulator.ransomware_simulator import SafeRansomwareSimulator

class SimulatorGatekeeperAdapter:
    """Adapter to funnel simulator actions through Gatekeeper."""
    
    def __init__(self, simulator: SafeRansomwareSimulator, gatekeeper: GatekeeperAgent, watchdog=None):
        """
        Initialize the adapter.
        
        Args:
            simulator: An instance of SafeRansomwareSimulator.
            gatekeeper: An instance of GatekeeperAgent.
            watchdog: Optional WatchdogAgent to receive screening context.
        """
        self.simulator = simulator
        self.gatekeeper = gatekeeper
        self.watchdog = watchdog
        
    def evaluate_file_access(self, file_path: Path) -> ScreeningResult:
        """
        Screen the file path before allowing the simulator to operate on it.
        
        Args:
            file_path: The path of the file the simulator intends to modify or create.
            
        Returns:
            ScreeningResult containing the Gatekeeper's verdict (ALLOW, MONITOR, SUSPICIOUS, BLOCK),
            risk score, and explainable reasons.
        """
        # We pass the file path to the gatekeeper for offline screening.
        # This operates on the string path (metadata screening), ensuring safety.
        return self.gatekeeper.screen_file(str(file_path))

    def evaluate_attack(self, file_paths: List[Path]) -> List[Tuple[Path, ScreeningResult]]:
        """
        Attempt to 'attack' a list of files by first screening each one.
        If Gatekeeper verdict is BLOCK, the simulated attack on that file is aborted.
        Otherwise, the simulator proceeds with the attack on that file.
        
        Returns a list of tuples containing the file path and its ScreeningResult.
        
        Args:
            file_paths: List of dummy file paths the simulator wants to target.
            
        Returns:
            List of (Path, ScreeningResult).
        """
        results = []
        for file_path in file_paths:
            result = self.evaluate_file_access(file_path)
            results.append((file_path, result))
            
            if result.is_blocked:
                # Abort simulation for this file
                continue
                
            # For ALLOW, MONITOR, SUSPICIOUS, register with Watchdog to provide context
            if self.watchdog is not None:
                self.watchdog.register_screening_result(result)
                
            # Then the simulator proceeds
            if file_path.exists():
                self.simulator.simulate_attack_damage([file_path])
                
        return results
