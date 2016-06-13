<!DOCTYPE html>
<head>
    <title>NetExplorer</title>
</head>
<body>
    <p1>NetExplorer</p1>
    <hr>
    <p>Hosts</p>
    %for host in hosts
        <tr>
            <td>{{host.name}}</td>
            <td>{{host.ips[0]}}</td>
            <td>{{host.macs[0]}}</td>
        </tr>
    %end
</body>
