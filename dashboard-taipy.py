from taipy.gui import Gui, notify
import pandas as pd
import webbrowser
import datetime

section_1="""
<center>
<|navbar|lov={[("page1")]}|>
</center>

<span style='color: red;'> ! HostShield Threat Intelligence Dashboard !</span>
=========================
<|layout|columns=1 3|
<|
###<span style='color: blue;'>!  Check the logs for threat ! </span>
<br/> 
<center>
<|file_selector|label=Upload log file|>
</center>
|>
<|
<center>
<|{logo}|image|height=250px|width=600px|on_action=image_action|>
</center>
|>
|>

"""

section_2 = """
##<span style='color: red;'>! ! Data Visualization ! !</span>
<|{dataset}|chart|mode=lines|x=EventTime|y[1]=SourceIPAddress|y[2]=ResourceName|color[1]=blue|color[2]=red|>
"""

section_3 = """
<|layout|columns= 1 5|
<|
## Custom Parameters
**Starting Date**\n\n<|{start_date}|date|not with_time|on_change=start_date_onchange|>
<br/><br/>
**Ending Date**\n\n<|{end_date}|date|not with_time|on_change=end_date_onchange|>
<br/>
<br/>
<|button|label=GO|on_action=button_action|>
|>
<|
<center> <h2>Dataset</h2><|{download_data}|file_download|on_action=download|>
</center>
<center>
<|{dataset}|table|page_size=10|height=500px|width=65%|>
</center>
|>
|>
"""
def image_action(state):
    webbrowser.open("https://taipy.io")

def get_data(path: str):
    dataset = pd.read_csv(path)
    dataset["EventTime"] = pd.to_datetime(dataset["EventTime"]).dt.date
    return dataset
def download(state):
    state.dataset.to_csv('download.csv')
    state.download_data = 'download.csv'

logo = "images/logo.png"
dataset = get_data("datasets/weather.csv")
start_date = datetime.date(2008, 12, 1)
end_date = datetime.date(2017, 6, 25)

Gui(page=section_1+section_2+section_3).run(dark_mode=False)