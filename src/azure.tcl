# Azure theme for Tkinter
# A simple theme to make the application look more modern

namespace eval ttk::theme::azure {
    variable colors
    array set colors {
        -fg             "#000000"
        -bg             "#ffffff"
        -disabledfg     "#999999"
        -disabledbg     "#f2f2f2"
        -selectfg       "#ffffff"
        -selectbg       "#4a6984"
        -accent         "#2d7ac7"
        -darker         "#2c3e50"
        -darkest        "#1e3244"
    }

    proc LoadImages {imgdir} {
        variable I
        foreach file [glob -directory $imgdir *.png] {
            set img [file tail [file rootname $file]]
            set I($img) [image create photo -file $file]
        }
    }

    ttk::style theme create azure -parent default -settings {
        ttk::style configure . \
            -background $colors(-bg) \
            -foreground $colors(-fg) \
            -troughcolor $colors(-bg) \
            -focuscolor $colors(-accent) \
            -selectbackground $colors(-selectbg) \
            -selectforeground $colors(-selectfg) \
            -fieldbackground $colors(-bg) \
            -font "TkDefaultFont" \
            -borderwidth 1 \
            -relief flat

        ttk::style configure TButton \
            -padding {8 4 8 4} \
            -anchor center

        ttk::style map TButton \
            -background [list active $colors(-accent) disabled $colors(-disabledbg)] \
            -foreground [list active $colors(-selectfg) disabled $colors(-disabledfg)]

        ttk::style configure TEntry \
            -padding {6 4} \
            -insertwidth 1

        ttk::style configure TNotebook \
            -tabmargins {2 5 2 0}
        ttk::style map TNotebook.Tab \
            -background [list selected $colors(-accent) active $colors(-darker) !active $colors(-darkest)] \
            -foreground [list selected $colors(-selectfg) active $colors(-selectfg) !active $colors(-fg)]

        ttk::style configure TProgressbar \
            -background $colors(-accent)

        ttk::style configure Treeview \
            -background $colors(-bg) \
            -foreground $colors(-fg) \
            -fieldbackground $colors(-bg)
        ttk::style map Treeview \
            -background [list selected $colors(-selectbg)] \
            -foreground [list selected $colors(-selectfg)]

        ttk::style configure TLabelframe \
            -borderwidth 2 \
            -relief groove
    }
}

proc set_theme {mode} {
    ttk::style theme use azure
    
    if {$mode eq "dark"} {
        ttk::style configure . \
            -background "#2c3e50" \
            -foreground "#ecf0f1" \
            -fieldbackground "#34495e"
            
        ttk::style map . \
            -background [list disabled "#2c3e50"] \
            -foreground [list disabled "#95a5a6"]
            
        ttk::style configure TButton \
            -background "#3498db" \
            -foreground "#ffffff"
        
        ttk::style configure TEntry \
            -fieldbackground "#34495e" \
            -foreground "#ecf0f1"
            
        ttk::style configure TNotebook \
            -background "#2c3e50"
            
        ttk::style configure TNotebook.Tab \
            -background "#34495e" \
            -foreground "#ecf0f1"
            
        ttk::style map TNotebook.Tab \
            -background [list selected "#3498db" active "#2980b9"] \
            -foreground [list selected "#ffffff" active "#ecf0f1"]
            
        ttk::style configure Treeview \
            -background "#34495e" \
            -foreground "#ecf0f1" \
            -fieldbackground "#34495e"
            
        ttk::style map Treeview \
            -background [list selected "#3498db"] \
            -foreground [list selected "#ffffff"]
    }
}

package provide ttk::theme::azure 1.0
ttk::theme::azure::LoadImages
