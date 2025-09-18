     layout: category
     title: SOC Posts
     category: soc
     permalink: /category/soc
     <h1>{{ page.title }}</h1>
<div class="post-list">
  {% for post in site.categories.soc %}
    <li>
      <h2 class="post-title"><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h2>
      <p class="post-meta">{{ post.date | date: "%b %-d, %Y" }}</p>
      {{ post.excerpt | strip_html }}
    </li>
  {% endfor %}
</div>
     ---
     All posts about Security Operations Centers.
