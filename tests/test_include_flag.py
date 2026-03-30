"""Tests for the --include command line flag."""

import subprocess
import sys

def test_include_flag(tmp_path):
    """Test that the --include flag correctly searches for files."""
    # Create a directory for included files
    include_dir = tmp_path / "lib"
    include_dir.mkdir()
    
    # Create an included file
    inc_file = include_dir / "useful.tal"
    inc_file.write_text("@print-hex INC JMP2r\n")
    
    # Create a main file that includes it
    main_file = tmp_path / "main.tal"
    main_file.write_text("|0100 ~useful.tal\nprint-hex\n")
    
    output_rom = tmp_path / "include_test.rom"
    
    # Run the assembler with the -I flag
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "yooxn",
            str(main_file),
            "-o",
            str(output_rom),
            "-I",
            str(include_dir),
        ],
        capture_output=True,
        text=True,
    )
    
    assert result.returncode == 0
    assert output_rom.exists()
    
    # Verify that it fails WITHOUT the -I flag
    output_rom_fail = tmp_path / "include_test_fail.rom"
    result_fail = subprocess.run(
        [
            sys.executable,
            "-m",
            "yooxn",
            str(main_file),
            "-o",
            str(output_rom_fail),
        ],
        capture_output=True,
        text=True,
    )
    
    assert result_fail.returncode != 0
    assert "Include file not found" in result_fail.stderr
