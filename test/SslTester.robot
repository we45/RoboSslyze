*** Settings ***
Library  /Users/abhaybhargav/Documents/Code/Python/RoboSslyze/robosslyze/RoboSslyze.py

*** Variables ***
${TARGET}  www.google.com

*** Test Cases ***
Test for SSL
    test ssl basic  ${TARGET}
    test ssl server headers  ${TARGET}