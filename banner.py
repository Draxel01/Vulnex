# banner.py
import random
from colorama import Fore, Style, init

# initialize colorama for consistent colors on all platforms
init(autoreset=True)

def show_banner():
    """
    Simple rotating banners (msfconsole-style). Adds color and author line.
    """
    banners = [
r"""
      .----.                                                                                                                                      
     /      \                                                                                                                                     
     |  ()  |                                                                                                                                     
     |      |                                                                                                                                     
     |  ()  |                                                                                                                                     
     \      /                                                                                                                                     
      '----'                                                                                                                                      
   [ Locking on target... ]                                                                                                                       
        """,

r"""
     ______     _       
    / ____/____(_)___ _ 
   / __/ / ___/ / __ `/ 
  / /___/ /  / / /_/ /  
 /_____/_/  /_/ \__,_/   
                        
      [ Vulnex Security Scanner ]
""",

r"""
 __     __     __     __   __     ______     __  __    
/\ \  _ \ \   /\ \   /\ "-.\ \   /\  __ \   /\ \/ /    
\ \ \/ ".\ \  \ \ \  \ \ \-.  \  \ \ \/\ \  \ \  _"-.  
 \ \__/".~\_\  \ \_\  \ \_\\"\_\  \ \_____\  \ \_\ \_\ 
  \/_/   \/_/   \/_/   \/_/ \/_/   \/_____/   \/_/\/_/ 
                                                      
""",

r"""
 __      __   _                    
 \ \    / /__| |__ ___ _ __  ___   
  \ \/\/ / -_) / _/ -_) '  \/ -_)  
   \_/\_/\___|_\__\___|_|_|_\___|  
                                   
   [ Vulnex by Draxel01 ]
""",

r"""
 __   __  ______  _   _  _   _  _____ 
 \ \ / / |  ____|| \ | || \ | ||  __ \
  \ V /  | |__   |  \| ||  \| || |__) |
   > <   |  __|  | . ` || . ` ||  ___/
  / . \  | |____ | |\  || |\  || |    
 /_/ \_\ |______||_| \_||_| \_||_|    
                                      
"""
    ]

    colors = [Fore.RED, Fore.CYAN, Fore.GREEN, Fore.MAGENTA, Fore.YELLOW, Fore.BLUE]
    color = random.choice(colors)

    banner = random.choice(banners)
    print(color + banner + Style.RESET_ALL)
    print(f"{Fore.MAGENTA}               By Draxel01{Style.RESET_ALL}\n")

